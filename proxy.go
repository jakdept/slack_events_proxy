package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func StatusHandler(statusCode int, status string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			_, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "could not read body", http.StatusBadRequest)
				return
			}
		}
		http.Error(w, status, statusCode)
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

func RestrictURIHandler(
	child http.Handler,
	uri ...string,
) http.Handler {
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

func (r reader) Read(p []byte) (int, error) {
	return r(p)
}

func BodyLimitHandler(child http.Handler, maxSize int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxSize {
			http.Error(w, "body over size limit", http.StatusRequestEntityTooLarge)
			return
		}
		left := maxSize
		in := r.Body

		limited := reader(func(p []byte) (n int, err error) {
			if left <= 0 {
				http.Error(w, "body over size limit", http.StatusRequestEntityTooLarge)
				panic(http.ErrAbortHandler) // abandon handlingthis request
			}
			if int64(len(p)) > left {
				p = p[0:left]
			}
			n, err = in.Read(p)
			left -= int64(n)
			return
		})
		r.Body = ioutil.NopCloser(limited)

		child.ServeHTTP(w, r)
	})
}

const (
	SlackSignatureVersion = "v0"
	SlackHeaderSignature  = "X-Slack-Signature"
	SlackHeaderTimestamp  = "X-Slack-Request-Timestamp"
)

func VerifySlackSignatureHandler(
	key string,
	expire time.Duration,
	child http.Handler,
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
		mac := hmac.New(sha256.New, []byte(key))
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
