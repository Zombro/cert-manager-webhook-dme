package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	certmgrv1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

const (
	defaultTTL = 600
)

var (
	GroupName = os.Getenv("GROUP_NAME")
	BaseUrl   = os.Getenv("DME_BASE_URL")
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	if BaseUrl == "" {
		panic("DME_BASE_URL must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&DMEDNSProviderSolver{},
	)
}

type DMEClient struct {
	apiKey     string
	apiSecret  string
	defaultTTL int
	baseUrl    string
	httpClient *http.Client
}

// DMEDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the
// `https://github.com/cert-manager/cert-manager/blob/master/pkg/acme/webhook/webhook.go`
// Solver interface.
type DMEDNSProviderSolver struct {
	// A Kubernetes 'clientset' is needed.
	// Ensure your webhook's service account has the required RBAC role
	//	assigned to it for interacting with the Kubernetes APIs you need.
	kubeClient *kubernetes.Clientset
	dmeClient  *DMEClient
}

// DMEDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type DMEDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	// either provide secret references to the API credentials:
	APIKeyRef    certmgrv1.SecretKeySelector `json:"apiKeyRef"`
	APISecretRef certmgrv1.SecretKeySelector `json:"apiSecretRef"`
	// or define the environment variable names API credentials are injected into:
	APIKeyEnvVar    string `json:"apiKeyEnvVar"`
	APISecretEnvVar string `json:"apiSecretEnvVar"`
	// misc config
	TTL *int `json:"ttl"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `dme` may be used as the name of a solver.
func (c *DMEDNSProviderSolver) Name() string {
	return "dme"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *DMEDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.V(2).Infoln("Start challenge", "fqdn", ch.ResolvedFQDN, "zone", ch.ResolvedZone, "key", ch.Key)
	c.setCredentials(ch)
	domainId, err := c.dmeClient.getDomainID(ch.ResolvedZone)
	if err != nil {
		return err
	}
	recordName := strings.Split(ch.ResolvedFQDN, ".")[0]
	err = c.dmeClient.createRecord(domainId, &DmeRecord{
		Name:        recordName,
		Type:        "TXT",
		Value:       ch.Key,
		GtdLocation: "DEFAULT",
		TTL:         c.dmeClient.defaultTTL,
	})
	if err != nil {
		return err
	}
	klog.V(2).Infoln("End challenge", "fqdn", ch.ResolvedFQDN, "zone", ch.ResolvedZone, "key", ch.Key)
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *DMEDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.V(2).Infoln("Start cleanup", "fqdn", ch.ResolvedFQDN, "zone", ch.ResolvedZone, "key", ch.Key)
	c.setCredentials(ch)
	domainId, err := c.dmeClient.getDomainID(ch.ResolvedZone)
	if err != nil {
		return err
	}
	// check if record exists
	recordName := strings.Split(ch.ResolvedFQDN, ".")[0]
	dmeRecords, err := c.dmeClient.getRecordsByName(domainId, recordName)
	if err != nil {
		return err
	}
	if dmeRecords != nil {
		// if multiple records, get record with matching value
		for _, record := range dmeRecords {
			// massage response value. wonky api behavior
			// DME wraps the value in quotes, effectively double-quoted, with inner quotes escaped.
			value, _ := strconv.Unquote(record.Value)
			if value == ch.Key {
				// delete matching record
				err := c.dmeClient.deleteRecord(domainId, record)
				if err != nil {
					return err
				}
				klog.V(2).Infoln("End cleanup", "fqdn", ch.ResolvedFQDN, "zone", ch.ResolvedZone, "key", ch.Key)
				return nil
			}
		}
		// nothing matched, return error
		return fmt.Errorf("no matching records found to delete")
	} else {
		return fmt.Errorf("record not found")
	}

}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *DMEDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	kubeClient, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.kubeClient = kubeClient
	c.dmeClient = &DMEClient{}
	c.dmeClient.defaultTTL = defaultTTL
	c.dmeClient.baseUrl = BaseUrl
	c.dmeClient.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
				PreferServerCipherSuites: true,
				InsecureSkipVerify:       false,
				MinVersion:               tls.VersionTLS12,
				MaxVersion:               tls.VersionTLS13,
			},
		},
	}

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (DMEDNSProviderConfig, error) {
	cfg := DMEDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}

func (c *DMEDNSProviderSolver) setCredentials(ch *v1alpha1.ChallengeRequest) error {
	var apiKey, apiSecret string
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	if cfg.APIKeyEnvVar != "" {
		apiKey = os.Getenv(cfg.APIKeyEnvVar)
		if apiKey == "" {
			klog.Warningf("Empty APIKeyEnvVar %q", cfg.APIKeyEnvVar)
		}
	} else if apiKey == "" {
		klog.V(3).InfoS("Getting APIKey from secretRef")
		apiKey, err = c.getSecret(cfg.APIKeyRef, ch)
		if err != nil {
			return err
		}
	}
	if cfg.APISecretEnvVar != "" {
		apiSecret = os.Getenv(cfg.APISecretEnvVar)
		if apiKey == "" {
			klog.Warningf("Empty APISecretEnvVar %q", cfg.APISecretEnvVar)
		}
	} else if apiSecret == "" {
		klog.V(3).InfoS("Getting APISecretfrom secretRef")
		apiSecret, err = c.getSecret(cfg.APISecretRef, ch)
		if err != nil {
			return err
		}
	}
	if apiKey == "" || apiSecret == "" {
		return fmt.Errorf("empty credentials")
	}
	c.dmeClient.apiKey = apiKey
	c.dmeClient.apiSecret = apiSecret
	return nil
}

func (c *DMEDNSProviderSolver) getSecret(ref certmgrv1.SecretKeySelector, ch *v1alpha1.ChallengeRequest) (string, error) {
	if ref.Key == "" || ref.Name == "" {
		return "", fmt.Errorf("no apiKeyRef for %q in secret '%s/%s'", ref.Name, ref.Key, ch.ResourceNamespace)
	}
	secret, err := c.kubeClient.CoreV1().Secrets(ch.ResourceNamespace).Get(context.TODO(), ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	apiKeyRef, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("no apiKeyRef for %q in secret '%s/%s'", ref.Name, ref.Key, ch.ResourceNamespace)
	}
	return string(apiKeyRef), nil
}

// Generates hmac from secret key
func (c *DMEClient) getToken(time string) (string, error) {
	h := hmac.New(sha1.New, []byte(c.apiSecret))
	_, err := h.Write([]byte(time))
	if err != nil {
		return "", err
	}
	sha := hex.EncodeToString(h.Sum(nil))
	return string(sha), nil
}

type DMERequest struct {
	url    string
	method string
	query  map[string]string
	body   []byte
}

type DmeDomainResponse struct {
	TotalRecords int         `json:"totalRecords"`
	TotalPages   int         `json:"totalPages"`
	Data         []DmeDomain `json:"data"`
	Page         int         `json:"page"`
}

type DmeDomain struct {
	ProcessMulti       bool     `json:"processMulti"`
	ActiveThirdParties []string `json:"activeThirdParties"`
	Created            int      `json:"created"`
	GtdEnabled         bool     `json:"gtdEnabled"`
	Updated            int      `json:"updated"`
	Folderid           int      `json:"folderid"`
	PendingActionId    int      `json:"pendingActionId"`
	Name               string   `json:"name"`
	Id                 int      `json:"id"`
}

type DmeRecordResponse struct {
	TotalRecords int         `json:"totalRecords"`
	TotalPages   int         `json:"totalPages"`
	Data         []DmeRecord `json:"data"`
	Page         int         `json:"page"`
}

type DmeRecord struct {
	Failover    bool   `json:"failover"`
	SourceId    int    `json:"sourceId"`
	DynamicDns  bool   `json:"dynamicDns"`
	HardLink    bool   `json:"hardLink"`
	TTL         int    `json:"ttl"`
	Failed      bool   `json:"failed"`
	Monitor     bool   `json:"monitor"`
	GtdLocation string `json:"gtdLocation"`
	Source      int    `json:"source"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	Id          int    `json:"id"`
	Type        string `json:"type"`
}

// Convenience. HMAC's request, returns body as bytes if successful
func (c *DMEClient) doRequest(rq *DMERequest) ([]byte, error) {
	var body io.Reader
	var urlx string
	if rq.body != nil {
		body = bytes.NewReader(rq.body)
	}
	if rq.query != nil {
		u, err := url.Parse(rq.url)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		for k, v := range rq.query {
			q.Add(k, v)
		}
		u.RawQuery = q.Encode()
		urlx = u.String()
	} else {
		urlx = rq.url
	}
	req, err := http.NewRequest(rq.method, urlx, body)
	if err != nil {
		return nil, err
	}
	time := time.Now().UTC().Format(time.RFC1123)
	hmac, err := c.getToken(time)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("x-dnsme-hmac", hmac)
	req.Header.Add("x-dnsme-apiKey", c.apiKey)
	req.Header.Add("x-dnsme-requestDate", time)
	klog.V(2).Infoln("Request", "url", urlx, "method", rq.method)
	if klog.V(3).Enabled() {
		klog.Infoln("Request body", string(rq.body))
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	klog.V(2).Infoln("Response", "status", res.StatusCode)
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if klog.V(3).Enabled() {
		klog.Infoln("Response body", string(b))
	}
	if res.StatusCode != 200 && res.StatusCode != 201 {
		return nil, fmt.Errorf("error: %d", res.StatusCode)
	}

	return b, nil
}

func (c *DMEClient) getDomainID(domain string) (int, error) {
	body, err := c.doRequest(&DMERequest{
		url:    fmt.Sprintf("%s%s", c.baseUrl, "/dns/managed"),
		method: http.MethodGet,
	})
	if err != nil {
		return 0, err
	}
	var domainResponse DmeDomainResponse
	err = json.Unmarshal(body, &domainResponse)
	if err != nil {
		return 0, err
	}
	for _, d := range domainResponse.Data {
		if d.Name == strings.TrimSuffix(domain, ".") {
			return d.Id, nil
		}
	}
	return 0, fmt.Errorf("domain not found")
}

func (c *DMEClient) createRecord(domainId int, record *DmeRecord) error {
	jsonData, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = c.doRequest(&DMERequest{
		url:    fmt.Sprintf("%s%s/%d/records/", c.baseUrl, "/dns/managed", domainId),
		method: http.MethodPost,
		body:   jsonData,
	})
	if err != nil {
		return err
	}
	return nil
}

func (c *DMEClient) deleteRecord(domainId int, record *DmeRecord) error {
	_, err := c.doRequest(&DMERequest{
		url:    fmt.Sprintf("%s%s/%d/records/%d", c.baseUrl, "/dns/managed", domainId, record.Id),
		method: http.MethodDelete,
	})
	if err != nil {
		return err
	}
	return nil
}

func (c *DMEClient) getRecordsByName(domainId int, recordName string) ([]*DmeRecord, error) {
	body, err := c.doRequest(&DMERequest{
		url:    fmt.Sprintf("%s%s/%d/records", c.baseUrl, "/dns/managed", domainId),
		method: http.MethodGet,
		query:  map[string]string{"recordName": recordName},
	})
	if err != nil {
		return nil, err
	}
	var recordResponse DmeRecordResponse
	err = json.Unmarshal(body, &recordResponse)
	if err != nil {
		return nil, err
	}
	records := []*DmeRecord{}
	for _, d := range recordResponse.Data {
		if d.Name == recordName && d.Type == "TXT" {
			records = append(records, &d)
		}
	}
	// nothing was found, but no errors
	return records, nil
}
