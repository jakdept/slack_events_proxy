package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifySlackSignatureHandler(t *testing.T) {
	for name, tc := range testdata_VerifySlackSignature {
		t.Run(name, func(t *testing.T) {
			tc := tc
			// t.Parallel()
			ts := httptest.NewServer(VerifySlackSignatureHandler(
				tc.key,
				tc.expire,
				tc.child,
			))

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
