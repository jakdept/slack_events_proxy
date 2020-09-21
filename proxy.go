package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kingpin"
)

var httpAllowedMethodsSet, httpAllowedURIsSet *bool

var (
	// required restrictions
	proxyTarget = kingpin.
			Flag("proxy-host", "proxy host for requests").
			Required()
	slackToken = kingpin.
			Flag("slack-token", "slack verification token").
			Envar("SLACK_TOKEN").Required()
	slackExpire = kingpin.
			Flag("slack-expire", "max age of slack timestamp").
			Envar("SLACK_EXPIRE").Default("30s")

	// handler restrictions
	httpAllowedMethods = kingpin.
				Flag("method", "methods to accept").
				Envar("HTTP_METHOD").Default(http.MethodPost)
	httpAllowedURIs = kingpin.
			Flag("uri", "uris to accept").
			Envar("HTTP_URI")
	httpMaxBytes = kingpin.
			Flag("read-limit", "max bytes to accept in body request").
			Envar("HTTP_READ_LIMIT").Default("4mb")

	// server timeouts
	httpReadTimeout = kingpin.
			Flag("read-timeout", "http timeout").
			Envar("HTTP_READ_TIMEOUT").Default("10s")
	httpWriteTimeout = kingpin.
				Flag("write-timeout", "http timeout").
				Envar("HTTP_WRITE_TIMEOUT").Default("10s")
	httpIdleTimeout = kingpin.
			Flag("idle-timeout", "http timeout (keepalive)").
			Envar("HTTP_IDLE_TIMEOUT").Default("120s")

	listen = kingpin.
		Flag("listen", "listen address both servers (multiple allowed)").
		Envar("LISTEN")
	mutualTLS = kingpin.
			Flag("mtls", "enable mtls on https-listen").Default("false")
	redirectTarget = kingpin.
			Flag("redirect-target", "target for http -> https redirect")
	autocert = kingpin.
			Flag("autocert", "use letsencrypt to automatically grab a TLS certificate").
			Default("false")
)

func openListeners(addrs []net.TCPAddr) (listeners []net.Listener, err error) {
	for _, addr := range *listen.TCPList() {
		if each, err := net.Listen(addr.Network(), addr.String()); err != nil {
			return nil, err
		} else {
			listeners = append(listeners, each)
		}
	}

	if len(listeners) < 1 {
		if each, err := net.Listen("tcp", ":http"); err != nil { //nolint
			return nil, err
		} else {
			listeners = append(listeners, each)
		}
	}
	return
}

func buildSrv() (srv *http.Server) {
	srv.ReadTimeout = *httpReadTimeout.Duration()
	srv.WriteTimeout = *httpWriteTimeout.Duration()
	srv.IdleTimeout = *httpIdleTimeout.Duration()
	return
}

func httpRedirectSrv() *http.Server {
	srv := buildSrv()
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Connection", "close")
		http.Redirect(w, req, *redirectTarget.String()+req.URL.String(), http.StatusMovedPermanently)
	})
	return srv
}

func httpProxySrv() *http.Server {
	srv := buildSrv()
	h := buildHandler()
	srv.Handler = h
	return srv
}

func buildHandler() (h http.Handler) {
	h = httputil.NewSingleHostReverseProxy(*proxyTarget.URL())
	h = VerifySlackSignatureHandler(h, *slackToken.String(), *slackExpire.Duration())

	if len(*httpAllowedMethods.String()) > 0 {
		h = RestrictMethodHandler(h, *httpAllowedMethods.Strings()...)
	}
	if len(*httpAllowedURIs.String()) > 0 {
		h = RestrictMethodHandler(h, *httpAllowedURIs.Strings()...)
	}

	if *httpMaxBytes.Int64() > 0 {
		h = BodyLimitHandler(h, *httpMaxBytes.Int64())
	}
	return
}

func tlsConfig() *tls.Config {
	return &tls.Config{
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519, // Go 1.8 only
		},
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

func buildHttps(mux http.Handler) *http.Server {

	return &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}
}

func main() {
	kingpin.Parse()

	h := buildHandler()
	srv := buildHttps(h)

	srv.ListenAndServeTLS("", "")

}

func RestrictMethodHandler(child http.Handler, methods ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, eachMethod := range methods {
			if r.Method == eachMethod {
				child.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
}

func RestrictURIHandler(child http.Handler, uri ...string) http.Handler {
	for i := 0; i < len(uri); {
		switch {

		case len(uri[i]) < 1:
			// remove empty URIs from list
			uri = append(uri[:i], uri[i+1:]...)

		case uri[i][:1] != "/":
			// make sure each uri starts with /
			uri[i] = "/" + uri[i]
			i++

		default:
			i++
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, eachURI := range uri {
			if eachURI == r.RequestURI {
				// exact matches
				child.ServeHTTP(w, r)
				return
			} else if eachURI[len(eachURI)-1:] == "/" &&
				strings.HasPrefix(r.RequestURI, eachURI) {
				// prefix matches if the uri ends in /
				child.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "uri not found", http.StatusNotFound)
	})
}

type reader func(p []byte) (int, error)

func (r reader) Read(p []byte) (int, error) { return r(p) }

func BodyLimitHandler(child http.Handler, maxSize int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxSize {
			http.Error(w, "body over size limit", http.StatusRequestEntityTooLarge)
			return
		}
		left := maxSize
		in := r.Body

		bodyTooLarge := errors.New("body over size limit")

		defer func() {
			p := recover()
			if p != nil {
				if pType, ok := p.(error); ok && pType == bodyTooLarge {
					http.Error(w, "body over size limit", http.StatusRequestEntityTooLarge)
					return
				}
			}
		}()

		limited := func(p []byte) (n int, err error) {
			if left <= 0 {
				panic(bodyTooLarge) // abandon handlingthis request
			}
			if int64(len(p)) > left {
				p = p[0:left]
			}
			n, err = in.Read(p)
			left -= int64(n)
			return
		}
		r.Body = ioutil.NopCloser(reader(limited))

		child.ServeHTTP(w, r)
	})
}

const (
	SlackSignatureVersion = "v0"
	SlackHeaderSignature  = "X-Slack-Signature"
	SlackHeaderTimestamp  = "X-Slack-Request-Timestamp"
)

func VerifySlackSignatureHandler(
	child http.Handler,
	token string,
	expire time.Duration,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// grab the timestamp on the request, and verify not stale
		tsStr := r.Header.Get(SlackHeaderTimestamp)
		tsInt, err := strconv.Atoi(tsStr)
		if err != nil {
			http.Error(w, "bad timestamp in "+SlackHeaderTimestamp, http.StatusBadRequest)
			return
		}
		ts := time.Unix(int64(tsInt), 0)

		if ts.Add(expire).Before(time.Now()) {
			http.Error(w, "timestamp expired", http.StatusUnauthorized)
			return
		}

		// grab the expected signature
		trimmed := strings.TrimPrefix(
			r.Header.Get(SlackHeaderSignature),
			SlackSignatureVersion+"=")
		expSig, err := hex.DecodeString(trimmed)
		if err != nil {
			http.Error(w, "bad signature", http.StatusBadRequest)
			return
		}

		// grab the contents of the body for signature generation
		// have to read the full body and verify checksum before calling child handler
		newBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		r.Body.Close()

		// calculate the current checksum
		mac := hmac.New(sha256.New, []byte(token))
		// by spec mac.Write always returns nil
		fmt.Fprintf(mac, "%s:%s:%s", SlackSignatureVersion, tsStr, string(newBody))

		calcSig := mac.Sum(nil)

		if !hmac.Equal(expSig, calcSig) {
			http.Error(w, "verification failed", http.StatusUnauthorized)
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewBuffer(newBody))
		child.ServeHTTP(w, r)
	})
}
