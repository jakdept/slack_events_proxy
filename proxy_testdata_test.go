package main

import (
	"net/http"
	"time"
)

var testdata_StatusHandler = map[string]int{
	"no content":    http.StatusNoContent,
	"StatusOK":      http.StatusOK,
	"access aenied": http.StatusUnauthorized,
	"not found":     http.StatusNotFound,
	"server error":  http.StatusInternalServerError,
}

type testdata_VerifySlackSignature_Request struct {
	Body       string
	Timestamp  string
	Signature  string
	StatusCode int
}

var testdata_VerifySlackSignature = map[string]struct {
	key      string
	expire   time.Duration
	child    http.Handler
	requests []testdata_VerifySlackSignature_Request
}{
	"default example": {
		key:    "8f742231b10e8888abcd99yyyzzz85a5",
		expire: time.Hour * 24 * 365 * 50, // expire in 50 years from timestamp
		child:  StatusHandler(http.StatusNoContent, ""),
		requests: []testdata_VerifySlackSignature_Request{
			{
				Body:       "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c",
				Timestamp:  "1531420618",
				Signature:  "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
				StatusCode: http.StatusNoContent,
			},
			{
				Body:       "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c",
				Timestamp:  "1531420618",
				Signature:  "v0=lolno",
				StatusCode: http.StatusBadRequest,
			},
			{
				Body:       "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c",
				Timestamp:  "1531420618",
				Signature:  "v0=baad",
				StatusCode: http.StatusUnauthorized,
			},
			{
				Body:       "",
				StatusCode: http.StatusMethodNotAllowed,
			},
			{
				Body:       "",
				Timestamp:  "lol123",
				StatusCode: http.StatusBadRequest,
			},
		},
	},
	"expired example": {
		key:    "8f742231b10e8888abcd99yyyzzz85a5",
		expire: time.Second,
		child:  StatusHandler(http.StatusNoContent, ""),
		requests: []testdata_VerifySlackSignature_Request{
			{
				Body:       "",
				Timestamp:  "1",
				Signature:  "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
				StatusCode: http.StatusUnauthorized,
			},
		},
	},
}
