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
	"log"
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
	flagProxyTarget = kingpin.
			Flag("proxy-host", "proxy host for requests").
			Required()
	flagSlackToken = kingpin.
			Flag("slack-token", "slack verification token").
			Envar("SLACK_TOKEN").Required()
	flagSlackExpire = kingpin.
			Flag("slack-expire", "max age of slack timestamp").
			Envar("SLACK_EXPIRE").Default("30s")

	// handler restrictions
	flagHttpAllowedMethods = kingpin.
				Flag("method", "methods to accept").
				Envar("HTTP_METHOD").Default(http.MethodPost)
	flagHttpAllowedURIs = kingpin.
				Flag("uri", "uris to accept").
				Envar("HTTP_URI")
	flagHttpMaxHeaderBytes = kingpin.
				Flag("header-limit", "max bytes to accept in body request").
				Envar("HTTP_HEADER_LIMIT").Default("4m")
	flagHttpMaxBodyBytes = kingpin.
				Flag("body-limit", "max bytes to accept in body request").
				Envar("HTTP_BODY_LIMIT").Default("4m")

	// server timeouts
	flagHttpReadTimeout = kingpin.
				Flag("read-timeout", "http timeout").
				Envar("HTTP_READ_TIMEOUT").Default("10s")
	flagHttpWriteTimeout = kingpin.
				Flag("write-timeout", "http timeout").
				Envar("HTTP_WRITE_TIMEOUT").Default("10s")
	flagHttpIdleTimeout = kingpin.
				Flag("idle-timeout", "http timeout (keepalive)").
				Envar("HTTP_IDLE_TIMEOUT").Default("120s")

	flagListen = kingpin.
			Flag("listen", "listen address both servers (multiple allowed)").
			Envar("LISTEN").Required()
	flagMutualTLS = kingpin.
			Flag("mtls", "enable mtls on https-listen").Default("false")
	flagTLSRedirect = kingpin.
			Flag("redirect-target", "target for http -> https redirect").
			Default("true")
	flagTLSCert = kingpin.
			Flag("tlsCert", "path to tls cert for https server").
			ExistingFile()
	flagTLSKey = kingpin.
			Flag("tlsKey", "path to tls key for https server").
			ExistingFile()
	flagAutocert = kingpin.
			Flag("autocert", "use letsencrypt to automatically grab a TLS certificate").
			Default("false")
)

func openListeners(addrs []*net.TCPAddr) (listeners []net.Listener, err error) {
	for _, addr := range addrs {
		if addr == nil {
			continue
		}
		each, err := net.Listen((*addr).Network(), (*addr).String())
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, each)
	}
	return
}

func buildSrv() (srv *http.Server) {
	srv.ReadTimeout = *flagHttpReadTimeout.Duration()
	srv.WriteTimeout = *flagHttpWriteTimeout.Duration()
	srv.IdleTimeout = *flagHttpIdleTimeout.Duration()
	srv.MaxHeaderBytes = *flagHttpMaxHeaderBytes.Int()
	return
}

func buildHandler() (h http.Handler) {
	// these get built outside in
	h = httputil.NewSingleHostReverseProxy(*flagProxyTarget.URL())
	h = VerifySlackSignatureHandler(h, *flagSlackToken.String(), *flagSlackExpire.Duration())

	if len(*flagHttpAllowedURIs.String()) > 0 {
		h = RestrictMethodHandler(h, *flagHttpAllowedURIs.Strings()...)
	}
	if len(*flagHttpAllowedMethods.String()) > 0 {
		h = RestrictMethodHandler(h, *flagHttpAllowedMethods.Strings()...)
	}
	if *flagHttpMaxBodyBytes.Int64() > 0 {
		h = BodyLimitHandler(h, *flagHttpMaxBodyBytes.Int64())
	}
	if *flagTLSRedirect.Bool() {
		h = HttpsRedirectHandler(h)
	}
	return
}

func tlsConfig() *tls.Config {
	config := &tls.Config{
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
	return config
}

func main() {
	kingpin.Parse()

	listeners, err := openListeners(*flagListen.TCPList())
	if err != nil {
		log.Fatal(err)
	}

	redirectSrv := buildSrv()
	redirectSrv.Handler = buildHandler()

	for _, listen := range listeners {
		redirectSrv.Serve(listen)
		// disabled until i get a bit more support in there?
		// redirectSrv.ServeTLS(listen, "", "")
	}
}

func HttpsRedirectHandler(child http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Println(req.URL)
		if req.URL.Scheme != "https" {
			w.Header().Set("Connection", "close")
			target := req
			target.URL.Scheme = "https"
			http.Redirect(w, req, target.URL.String(), http.StatusMovedPermanently)
		}
	})
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
