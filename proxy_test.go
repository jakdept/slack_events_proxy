package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestStatusHandler(t *testing.T) {
	for body, statusCode := range testdataStatusHandler {
		t.Run(body, func(t *testing.T) {
			// t.Parallel()

			body, statusCode := body, statusCode
			ts := httptest.NewServer(StatusHandler(statusCode, body))
			defer ts.Close()

			resp, err := http.Get(ts.URL)
			require.NoError(t, err)

			assert.Equal(t, statusCode, resp.StatusCode)
			respBytes, err := ioutil.ReadAll(resp.Body)
			assert.NoError(t, err)
			assert.Equal(t, body+"\n", string(respBytes))
		})
	}
}

func TestHttpsRedirectHandler(t *testing.T) {
	srv := httptest.NewServer(HttpsRedirectHandler(
		StatusHandler(http.StatusNoContent, "")))
	defer srv.Close()

	c := srv.Client()
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := c.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
}

func TestHttpsRedirectHandlerNoModify(t *testing.T) {
	srv := httptest.NewTLSServer(HttpsRedirectHandler(
		StatusHandler(http.StatusNoContent, "")))
	defer srv.Close()

	c := srv.Client()
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	log.Println(srv.URL)
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := c.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestResetrictMethodHandler(t *testing.T) {
	ts := httptest.NewServer(RestrictMethodHandler(
		StatusHandler(http.StatusOK, "ok"),
		http.MethodGet,
		http.MethodPost,
	))
	defer ts.Close()

	for method, statusCode := range testdataRestrictMethodHandler {
		t.Run(method, func(t *testing.T) {
			// t.Parallel()
			req, err := http.NewRequest(method, ts.URL, nil)
			require.NoError(t, err)
			resp, err := ts.Client().Do(req)
			require.NoError(t, err)
			assert.Equal(t, statusCode, resp.StatusCode)
		})
	}
}

func TestRestrictURIHandler(t *testing.T) {
	ts := httptest.NewServer(RestrictURIHandler(
		StatusHandler(http.StatusNoContent, ""),
		"/allowed/specific",
		"allowed/odd",
		"",
		"/allowed/generic/",
	))
	defer ts.Close()

	for uri, statusCode := range testdataRestrictURIHandler {
		t.Run("-"+uri, func(t *testing.T) {
			// t.Parallel()
			resp, err := ts.Client().Get(ts.URL + "/" + strings.TrimPrefix(uri, "/"))
			require.NoError(t, err)
			assert.Equal(t, statusCode, resp.StatusCode)
		})
	}
}

func TestBodyLimitHandler(t *testing.T) {
	ts := httptest.NewServer(BodyLimitHandler(
		StatusHandler(http.StatusNoContent, ""), 64))
	defer ts.Close()

	resp, err := http.Post(ts.URL, "text/text",
		strings.NewReader("this is just fine"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	resp, err = http.Post(ts.URL, "text/text",
		strings.NewReader(strings.Repeat("this is too long ", 1<<10)))
	require.NoError(t, err)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

	unlimited := func(p []byte) (int, error) {
		return copy(p, []byte(strings.Repeat("this is unlimited ", 1<<20))), nil
	}
	resp, err = http.Post(ts.URL, "text/text", reader(unlimited))
	require.NoError(t, err)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

func TestVerifySlackSignatureHandler(t *testing.T) {
	for name, tc := range testdataVerifySlackSignature {
		t.Run(name, func(t *testing.T) {
			tc := tc
			// t.Parallel()
			ts := httptest.NewServer(VerifySlackSignatureHandler(
				tc.child,
				tc.key,
				tc.expire,
			))
			defer ts.Close()

			for testReqID, testReq := range tc.requests {
				testReq := testReq
				eachReq, err := http.NewRequest(
					http.MethodGet,
					ts.URL,
					strings.NewReader(testReq.Body))
				require.NoError(t, err, "req %d", testReqID)

				eachReq.Header.Add(SlackHeaderTimestamp, testReq.Timestamp)
				eachReq.Header.Add(SlackHeaderSignature, testReq.Signature)

				resp, err := ts.Client().Do(eachReq)

				assert.NoError(t, err, "req %d", testReqID)
				assert.Equal(t, testReq.StatusCode, resp.StatusCode)
			}
		})
	}
}
