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
		http.Error(w, status, statusCode)
	})
}

func RestrictMethodHandler(
	denied, allowed http.Handler,
	methods ...string,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, eachMethod := range methods {
			if r.Method == eachMethod {
				allowed.ServeHTTP(w, r)
			} else {
				denied.ServeHTTP(w, r)
			}
		}
	})
}

func RestrictURIHandler(
	allowed, denied http.Handler,
	uri ...string,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, eachUri := range uri {
			if len(eachUri) < 1 {
				denied.ServeHTTP(w, r)
				return
			}

			if eachUri[:1] != "/" {
				eachUri = "/" + eachUri
			}

			if eachUri == r.RequestURI {
				allowed.ServeHTTP(w, r)
			} else if eachUri[len(eachUri)-1:] == "/" &&
				strings.HasPrefix(r.RequestURI, eachUri) {
				allowed.ServeHTTP(w, r)
			} else {
				denied.ServeHTTP(w, r)
			}
		}
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
