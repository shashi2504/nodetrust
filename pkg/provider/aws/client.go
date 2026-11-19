package aws

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodetrust/pkg/provider"
)

// DefaultIMDS is the instance metadata service.
const DefaultIMDS = "http://169.254.169.254"

// Client talks to EC2 and S3 with the instance role's credentials.
type Client struct {
	Region string
	HTTP   *http.Client
	// Endpoints; empty means the public AWS endpoint for Region. Tests set them.
	EC2Endpoint string // e.g. https://ec2.ap-south-1.amazonaws.com
	S3Endpoint  string // e.g. https://s3.ap-south-1.amazonaws.com (path-style requests)
	ASEndpoint  string // e.g. https://autoscaling.ap-south-1.amazonaws.com
	IMDS        string
	// Static credentials skip IMDS (development only).
	Static *Credentials
	Now    func() time.Time

	mu    sync.Mutex
	creds *Credentials
}

// New returns a client for the region the instance runs in (from IMDS when
// region is empty).
func New(ctx context.Context, region string) (*Client, error) {
	c := &Client{Region: region, HTTP: &http.Client{Timeout: 30 * time.Second}, IMDS: DefaultIMDS, Now: time.Now}
	if c.Region == "" {
		r, err := c.imdsGet(ctx, "/latest/meta-data/placement/region")
		if err != nil {
			return nil, fmt.Errorf("aws: region from IMDS: %w", err)
		}
		c.Region = strings.TrimSpace(r)
	}
	return c, nil
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) httpc() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// --- IMDSv2 and credentials -----------------------------------------------------

func (c *Client) imdsGet(ctx context.Context, path string) (string, error) {
	base := c.IMDS
	if base == "" {
		base = DefaultIMDS
	}
	req, _ := http.NewRequestWithContext(ctx, "PUT", base+"/latest/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
	resp, err := c.httpc().Do(req)
	if err != nil {
		return "", err
	}
	tok, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("IMDS token: HTTP %d", resp.StatusCode)
	}
	req, _ = http.NewRequestWithContext(ctx, "GET", base+path, nil)
	req.Header.Set("X-aws-ec2-metadata-token", string(tok))
	resp, err = c.httpc().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("IMDS %s: HTTP %d", path, resp.StatusCode)
	}
	return string(b), nil
}

// Credentials returns the instance role's credentials, refreshed five
// minutes before they expire.
func (c *Client) Credentials(ctx context.Context) (Credentials, error) {
	if c.Static != nil {
		return *c.Static, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.creds != nil && c.now().Add(5*time.Minute).Before(c.creds.Expires) {
		return *c.creds, nil
	}
	const p = "/latest/meta-data/iam/security-credentials/"
	role, err := c.imdsGet(ctx, p)
	if err != nil {
		return Credentials{}, fmt.Errorf("aws: instance role: %w", err)
	}
	role = strings.TrimSpace(strings.SplitN(role, "\n", 2)[0])
	if role == "" {
		return Credentials{}, errors.New("aws: the instance has no IAM role")
	}
	raw, err := c.imdsGet(ctx, p+role)
	if err != nil {
		return Credentials{}, fmt.Errorf("aws: credentials for %s: %w", role, err)
	}
	var v struct {
		Code, AccessKeyId, SecretAccessKey, Token string
		Expiration                                time.Time
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil || v.Code != "Success" || v.AccessKeyId == "" {
		return Credentials{}, fmt.Errorf("aws: credentials for %s: code %q %v", role, v.Code, err)
	}
	c.creds = &Credentials{AccessKeyID: v.AccessKeyId, SecretAccessKey: v.SecretAccessKey, SessionToken: v.Token, Expires: v.Expiration}
	return *c.creds, nil
}

// --- EC2 ------------------------------------------------------------------------

// APIError is an error response from an AWS API.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("aws: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

func (c *Client) ec2(ctx context.Context, form url.Values, out any) error {
	ep := c.EC2Endpoint
	if ep == "" {
		ep = "https://ec2." + c.Region + ".amazonaws.com"
	}
	return c.query(ctx, ep, "ec2", "2016-11-15", form, out)
}

// autoscaling calls the Auto Scaling query API.
func (c *Client) autoscaling(ctx context.Context, form url.Values, out any) error {
	ep := c.ASEndpoint
	if ep == "" {
		ep = "https://autoscaling." + c.Region + ".amazonaws.com"
	}
	return c.query(ctx, ep, "autoscaling", "2011-01-01", form, out)
}

// query sends one signed AWS query API request (EC2 and Auto Scaling use
// the same form-encoded POST, with different error XML).
func (c *Client) query(ctx context.Context, ep, service, version string, form url.Values, out any) error {
	form.Set("Version", version)
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, "POST", ep+"/", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	cr, err := c.Credentials(ctx)
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(body))
	Sign(req, cr, c.Region, service, hex.EncodeToString(h[:]), c.now())
	resp, err := c.httpc().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		var e struct {
			Errors []struct{ Code, Message string } `xml:"Errors>Error"` // EC2
			Error  struct{ Code, Message string }   `xml:"Error"`        // Auto Scaling
		}
		xml.Unmarshal(b, &e)
		ae := &APIError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
		if len(e.Errors) > 0 {
			ae.Code, ae.Message = e.Errors[0].Code, e.Errors[0].Message
		}
		return ae
	}
	if out == nil {
		return nil
	}
	return xml.Unmarshal(b, out)
}

// Instance is what the verifier needs to know about a worker, all from the
// EC2 control plane (never from the instance).
type Instance struct {
	ID           string
	ImageID      string
	PrivateIP    string
	State        string
	RootVolumeID string
	Zone         string
	LaunchTime   time.Time
	Tags         map[string]string
	SubnetID     string
	VPCID        string
	Volumes      []string // every EBS volume attached
	ENIs         []ENI
}

// ENI is one network interface of an instance and its security groups.
type ENI struct {
	ID     string
	Groups []string
}

type xmlInstance struct {
	ID         string    `xml:"instanceId"`
	ImageID    string    `xml:"imageId"`
	PrivateIP  string    `xml:"privateIpAddress"`
	State      string    `xml:"instanceState>name"`
	RootDevice string    `xml:"rootDeviceName"`
	Zone       string    `xml:"placement>availabilityZone"`
	LaunchTime time.Time `xml:"launchTime"`
	SubnetID   string    `xml:"subnetId"`
	VPCID      string    `xml:"vpcId"`
	Devices    []struct {
		Name   string `xml:"deviceName"`
		Volume string `xml:"ebs>volumeId"`
	} `xml:"blockDeviceMapping>item"`
	ENIs []struct {
		ID     string   `xml:"networkInterfaceId"`
		Groups []string `xml:"groupSet>item>groupId"`
	} `xml:"networkInterfaceSet>item"`
	Tags []struct {
		Key   string `xml:"key"`
		Value string `xml:"value"`
	} `xml:"tagSet>item"`
}

// DescribeInstances lists instances matching the filters (name -> values),
// following pagination.
func (c *Client) DescribeInstances(ctx context.Context, filters map[string][]string) ([]Instance, error) {
	var out []Instance
	token := ""
	for page := 0; page < 100; page++ {
		form := url.Values{"Action": {"DescribeInstances"}}
		i := 1
		for _, name := range sortedKeys(filters) {
			form.Set("Filter."+strconv.Itoa(i)+".Name", name)
			for j, v := range filters[name] {
				form.Set("Filter."+strconv.Itoa(i)+".Value."+strconv.Itoa(j+1), v)
			}
			i++
		}
		if token != "" {
			form.Set("NextToken", token)
		}
		var r struct {
			Reservations []struct {
				Instances []xmlInstance `xml:"instancesSet>item"`
			} `xml:"reservationSet>item"`
			NextToken string `xml:"nextToken"`
		}
		if err := c.ec2(ctx, form, &r); err != nil {
			return nil, err
		}
		for _, res := range r.Reservations {
			for _, x := range res.Instances {
				in := Instance{ID: x.ID, ImageID: x.ImageID, PrivateIP: x.PrivateIP, State: x.State, Zone: x.Zone,
					LaunchTime: x.LaunchTime, Tags: map[string]string{}, SubnetID: x.SubnetID, VPCID: x.VPCID}
				for _, d := range x.Devices {
					if d.Name == x.RootDevice {
						in.RootVolumeID = d.Volume
					}
					if d.Volume != "" {
						in.Volumes = append(in.Volumes, d.Volume)
					}
				}
				for _, e := range x.ENIs {
					in.ENIs = append(in.ENIs, ENI{ID: e.ID, Groups: e.Groups})
				}
				for _, t := range x.Tags {
					in.Tags[t.Key] = t.Value
				}
				out = append(out, in)
			}
		}
		if r.NextToken == "" {
			return out, nil
		}
		token = r.NextToken
	}
	return nil, errors.New("aws: DescribeInstances: too many pages")
}

// EKPublic implements provider.EndorsementProvider with
// ec2:GetInstanceTpmEkPub.
func (c *Client) EKPublic(ctx context.Context, id provider.InstanceID, kt provider.EKKeyType) (crypto.PublicKey, error) {
	if kt != provider.EKRSA2048 && kt != provider.EKECCP384 {
		return nil, fmt.Errorf("%w: EK key type %q", provider.ErrUnsupported, kt)
	}
	var r struct {
		KeyValue string `xml:"keyValue"`
	}
	err := c.ec2(ctx, url.Values{"Action": {"GetInstanceTpmEkPub"}, "InstanceId": {string(id)},
		"KeyType": {string(kt)}, "KeyFormat": {"der"}}, &r)
	var ae *APIError
	if errors.As(err, &ae) {
		switch {
		case strings.HasPrefix(ae.Code, "InvalidInstanceID"):
			return nil, fmt.Errorf("%w: %v", provider.ErrNotFound, err)
		case ae.Code == "UnsupportedOperation" || ae.Code == "InvalidParameterValue":
			return nil, fmt.Errorf("%w: %v", provider.ErrUnsupported, err)
		}
	}
	if err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.KeyValue))
	if err != nil {
		return nil, fmt.Errorf("aws: EK of %s: %w", id, err)
	}
	return x509.ParsePKIXPublicKey(der)
}

// --- S3 -------------------------------------------------------------------------

// GetObject reads an S3 object (path-style request), up to max bytes.
func (c *Client) GetObject(ctx context.Context, bucket, key string, max int64) ([]byte, error) {
	ep := c.S3Endpoint
	if ep == "" {
		ep = "https://s3." + c.Region + ".amazonaws.com"
	}
	u := ep + "/" + uriEncode(bucket, true) + "/" + uriEncode(key, false)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Amz-Content-Sha256", EmptySHA256)
	cr, err := c.Credentials(ctx)
	if err != nil {
		return nil, err
	}
	Sign(req, cr, c.Region, "s3", EmptySHA256, c.now())
	resp, err := c.httpc().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		var e struct{ Code, Message string }
		xml.Unmarshal(b, &e)
		return nil, &APIError{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("aws: s3://%s/%s is larger than %d bytes", bucket, key, max)
	}
	return bytes.Clone(b), nil
}

func sortedKeys(m map[string][]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
}
