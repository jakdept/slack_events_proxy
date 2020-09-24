package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/units"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenListeners(t *testing.T) {
	flagAutocertDomainsSetByUser = new(bool)
	for name, td := range testdataOpenListeners {
		t.Run(name, func(t *testing.T) {
			td := td
			out, err := openListeners(td.in)
			if td.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, td.err)
			}
			require.Equal(t, len(td.out), len(out),
				"expected %s listeners have %s", len(td.out), len(out))
			for id := range out {
				assert.Equal(t, td.out[id], out[id].Addr().String())
				assert.NoError(t, out[id].Close())
			}
		})
	}
}

func TestBuildSrv(t *testing.T) {
	*flagHttpReadTimeout = time.Second
	*flagHttpWriteTimeout = time.Second
	*flagHttpIdleTimeout = time.Second
	*flagHttpMaxHeaderBytes = units.Base2Bytes(10)
	_ = buildSrv()
}

func TestTLSConfig(t *testing.T) {
	//todo
	_, _ = tlsConfig()
}

func TestBuildHandler(t *testing.T) {
	// backend target doesn't matter, it never gets there
	*flagProxyTarget = &url.URL{Scheme: "http", Host: "127.0.0.1:80"}
	for name, tc := range testdataBuildHandler {
		t.Run(name, func(t *testing.T) {
			*flagHttpAllowedURIs = tc.allowedURI
			flagHttpAllowedURIsSetByUser = new(bool)
			*flagHttpAllowedURIsSetByUser = len(tc.allowedURI) > 0
			*flagHttpAllowedMethods = tc.allowedMethod
			flagHttpAllowedMethodsSetByUser = new(bool)
			*flagHttpAllowedMethodsSetByUser = len(tc.allowedMethod) > 0
			*flagHttpMaxBodyBytes = units.Base2Bytes(tc.maxBodyBytes)

			tcSrv := httptest.NewServer(buildHandler())
			defer tcSrv.Close()
			resp, err := http.Post(tcSrv.URL, "", strings.NewReader(tc.Body))
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, tc.expStatusCode, resp.StatusCode)
		})
	}
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
