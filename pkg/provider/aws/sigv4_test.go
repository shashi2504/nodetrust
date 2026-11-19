package aws

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Examples from the AWS Signature Version 4 documentation.
func TestSignIAMExample(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	Sign(req, Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
		"us-east-1", "iam", EmptySHA256, now)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestSignS3GetObjectExample(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	req.Header.Set("X-Amz-Content-Sha256", EmptySHA256)
	now, _ := time.Parse("20060102T150405Z", "20130524T000000Z")
	Sign(req, Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		"us-east-1", "s3", EmptySHA256, now)
	got := req.Header.Get("Authorization")
	if !strings.HasSuffix(got, "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") ||
		!strings.Contains(got, "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date") {
		t.Fatalf("got %s", got)
	}
}

func TestSessionTokenIsSigned(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://ec2.ap-south-1.amazonaws.com/", nil)
	Sign(req, Credentials{AccessKeyID: "A", SecretAccessKey: "S", SessionToken: "T"}, "ap-south-1", "ec2", EmptySHA256, time.Now())
	if req.Header.Get("X-Amz-Security-Token") != "T" || !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Fatalf("%v", req.Header)
	}
}
