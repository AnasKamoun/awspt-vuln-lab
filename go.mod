// Intentionally vulnerable Go manifest (old CVE-bearing pins) for SCA testing.
module github.com/AnasKamoun/awspt-vuln-lab

go 1.20

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.6.0
	gopkg.in/yaml.v2 v2.2.1
	github.com/gorilla/websocket v1.4.0
	github.com/miekg/dns v1.0.8
)
