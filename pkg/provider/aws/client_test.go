package aws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nodetrust/pkg/provider"
	"nodetrust/pkg/provider/conformance"
)

var fixedNow, _ = time.Parse(time.RFC3339, "2026-11-18T10:00:00Z")

// fakeIMDS serves IMDSv2: a token is required for every read.
func fakeIMDS(t *testing.T, fetches *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && r.URL.Path == "/latest/api/token" {
			fmt.Fprint(w, "tok")
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "tok" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/latest/meta-data/placement/region":
			fmt.Fprint(w, "ap-south-1")
		case "/latest/meta-data/iam/security-credentials/":
			fmt.Fprint(w, "nodetrust-verifier")
		case "/latest/meta-data/iam/security-credentials/nodetrust-verifier":
			atomic.AddInt32(fetches, 1)
			fmt.Fprintf(w, `{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secret","Token":"session","Expiration":%q}`,
				fixedNow.Add(time.Hour).Format(time.RFC3339))
		default:
			w.WriteHeader(404)
		}
	}))
}

// checkSigned re-signs a copy of r with the expected credentials and
// compares the Authorization header, so a wrong body hash or a missing
// header fails the test.
func checkSigned(t *testing.T, r *http.Request, body []byte, service string) {
	t.Helper()
	cp, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), nil)
	for k, v := range r.Header {
		if k != "Authorization" && k != "User-Agent" && k != "Accept-Encoding" && k != "Content-Length" {
			cp.Header[k] = v
		}
	}
	ph := EmptySHA256
	if len(body) > 0 {
		ph = sha(body)
	}
	Sign(cp, Credentials{AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "secret", SessionToken: "session"}, "ap-south-1", service, ph, fixedNow)
	if got, want := r.Header.Get("Authorization"), cp.Header.Get("Authorization"); got != want {
		t.Errorf("signature:\n got  %s\n want %s", got, want)
	}
}

const describeXML = `<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>r</requestId>
  <reservationSet><item><reservationId>r-1</reservationId><instancesSet>
    <item>
      <instanceId>i-079cec283e5944e99</instanceId><imageId>ami-02dc3031448c845a0</imageId>
      <instanceState><code>16</code><name>running</name></instanceState>
      <privateIpAddress>10.42.18.108</privateIpAddress><launchTime>2026-11-18T10:38:00.000Z</launchTime>
      <rootDeviceName>/dev/sda1</rootDeviceName>
      <blockDeviceMapping>
        <item><deviceName>/dev/sdb</deviceName><ebs><volumeId>vol-data</volumeId></ebs></item>
        <item><deviceName>/dev/sda1</deviceName><ebs><volumeId>vol-084c34c32fbb06e85</volumeId></ebs></item>
      </blockDeviceMapping>
      <tagSet><item><key>role</key><value>worker</value></item></tagSet>
    </item>
  </instancesSet></item></reservationSet>
  %s
</DescribeInstancesResponse>`

func fakeEC2(t *testing.T, ek []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		checkSigned(t, r, body, "ec2")
		f, _ := url.ParseQuery(string(body))
		switch f.Get("Action") {
		case "DescribeInstances":
			if f.Get("Filter.1.Name") != "instance-state-name" || f.Get("Filter.2.Name") != "tag:role" || f.Get("Filter.2.Value.1") != "worker" {
				t.Errorf("filters %v", f)
			}
			next := "<nextToken>p2</nextToken>"
			if f.Get("NextToken") == "p2" {
				next = ""
			}
			fmt.Fprintf(w, describeXML, next)
		case "GetInstanceTpmEkPub":
			if f.Get("InstanceId") != "i-079cec283e5944e99" {
				w.WriteHeader(400)
				fmt.Fprint(w, `<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code><Message>The instance ID does not exist</Message></Error></Errors></Response>`)
				return
			}
			fmt.Fprintf(w, `<GetInstanceTpmEkPubResponse><instanceId>%s</instanceId><keyType>%s</keyType><keyFormat>der</keyFormat><keyValue>%s</keyValue></GetInstanceTpmEkPubResponse>`,
				f.Get("InstanceId"), f.Get("KeyType"), base64.StdEncoding.EncodeToString(ek))
		default:
			w.WriteHeader(400)
		}
	}))
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func newTestClient(t *testing.T, ek []byte, fetches *int32) *Client {
	imds, ec2 := fakeIMDS(t, fetches), fakeEC2(t, ek)
	t.Cleanup(imds.Close)
	t.Cleanup(ec2.Close)
	c := &Client{IMDS: imds.URL, EC2Endpoint: ec2.URL, Now: func() time.Time { return fixedNow }}
	r, err := c.imdsGet(context.Background(), "/latest/meta-data/placement/region")
	if err != nil {
		t.Fatal(err)
	}
	c.Region = r
	return c
}

func TestDescribeInstances(t *testing.T) {
	var n int32
	c := newTestClient(t, nil, &n)
	ins, err := c.DescribeInstances(context.Background(), map[string][]string{
		"tag:role": {"worker"}, "instance-state-name": {"running"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ins) != 2 { // two pages
		t.Fatalf("%d instances", len(ins))
	}
	in := ins[0]
	if in.ID != "i-079cec283e5944e99" || in.ImageID != "ami-02dc3031448c845a0" || in.PrivateIP != "10.42.18.108" ||
		in.RootVolumeID != "vol-084c34c32fbb06e85" || in.State != "running" || in.Tags["role"] != "worker" || in.LaunchTime.IsZero() {
		t.Fatalf("%+v", in)
	}
	if n != 1 {
		t.Errorf("credentials fetched %d times, want once (cached)", n)
	}
}

func TestEndorsementConformance(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	var n int32
	conformance.RunEndorsement(t, conformance.EndorsementEnv{
		Provider: newTestClient(t, der, &n),
		Instance: "i-079cec283e5944e99",
		KeyType:  provider.EKRSA2048,
		Want:     &k.PublicKey,
		Unknown:  "i-00000000000000000",
	})
}

func TestGetObject(t *testing.T) {
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkSigned(t, r, nil, "s3")
		switch r.URL.Path {
		case "/bkt/manifests/ami-1/manifest.json.gz":
			fmt.Fprint(w, "content")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
		}
	}))
	defer s3.Close()
	c := &Client{Region: "ap-south-1", S3Endpoint: s3.URL, Now: func() time.Time { return fixedNow },
		Static: &Credentials{AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "secret", SessionToken: "session"}}
	b, err := c.GetObject(context.Background(), "bkt", "manifests/ami-1/manifest.json.gz", 100)
	if err != nil || string(b) != "content" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := c.GetObject(context.Background(), "bkt", "manifests/ami-1/manifest.json.gz", 3); err == nil {
		t.Fatal("size limit not enforced")
	}
	_, err = c.GetObject(context.Background(), "bkt", "nope", 100)
	if ae, ok := err.(*APIError); !ok || ae.Code != "NoSuchKey" {
		t.Fatalf("%v", err)
	}
}

func TestNoRoleIsAnError(t *testing.T) {
	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			fmt.Fprint(w, "tok")
			return
		}
		w.WriteHeader(404)
	}))
	defer imds.Close()
	c := &Client{Region: "ap-south-1", IMDS: imds.URL}
	if _, err := c.Credentials(context.Background()); err == nil || !strings.Contains(err.Error(), "instance role") {
		t.Fatalf("%v", err)
	}
}
