# slack_events_proxy
A HTTP proxy to verify Slack Events API payloads and forward them onto internal infrastructure

Included package "slackverify" implements all verification methods from:

Relevant Links:
* https://api.slack.com/authentication/verifying-requests-from-slack

* https://api.slack.com/authentication/verifying-requests-from-slack#mutual_tls

* https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go

* https://blog.cloudflare.com/exposing-go-on-the-internet/