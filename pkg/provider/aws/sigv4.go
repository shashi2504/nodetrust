// Package aws is the AWS side of nodetrust's cloud seams, written against
// the AWS HTTP APIs with the standard library only: Signature Version 4,
// instance-role credentials from IMDSv2, the two EC2 calls the verifier
// needs (DescribeInstances, GetInstanceTpmEkPub) and S3 GetObject.
//
// The verifier host has an IAM role; nothing here reads keys from disk.
package aws

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials are temporary (or static) AWS credentials.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expires         time.Time // zero for static credentials
}

// EmptySHA256 is the payload hash of an empty body.
const EmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// uriEncode encodes a string the way SigV4 wants: every byte except
// unreserved characters, and "/" kept when encodeSlash is false.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~' || (c == '/' && !encodeSlash) {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	var parts []string
	for k, vs := range q {
		for _, v := range vs {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// Sign adds the SigV4 Authorization header (and X-Amz-Date, and
// X-Amz-Security-Token for temporary credentials) to req. payloadHash is the
// hex SHA-256 of the body. Every header already on req is signed, plus Host.
func Sign(req *http.Request, c Credentials, region, service, payloadHash string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	day := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	headers := map[string]string{"host": host}
	for k, vs := range req.Header {
		if strings.EqualFold(k, "Authorization") {
			continue
		}
		headers[strings.ToLower(k)] = strings.Join(strings.Fields(strings.Join(vs, ",")), " ")
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k + ":" + headers[k] + "\n")
	}
	signed := strings.Join(names, ";")

	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if service != "s3" {
		// Every service but S3 wants the path encoded once more.
		path = uriEncode(path, false)
	}
	creq := strings.Join([]string{req.Method, path, canonicalQuery(req.URL.Query()), ch.String(), signed, payloadHash}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	h := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])

	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}
