/*
run me:
````
$ TEST_ZONE_NAME=grug.io. DNS_SERVER=ns1.sandbox.dnsmadeeasy.com:53 make test
````
*/

package main

import (
	"flag"
	"os"
	"testing"
	"time"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
	"k8s.io/klog/v2"
)

var (
	// "grug.io."
	zone = os.Getenv("TEST_ZONE_NAME")
	// "ns1.sandbox.dnsmadeeasy.com:53"
	dns_server = os.Getenv("DNS_SERVER")
)

func TestRunsSuite(t *testing.T) {
	klog.InitFlags(nil)
	defer klog.Flush()
	flag.Set("v", "2")
	flag.Parse()

	fixture := acmetest.NewFixture(&DMEDNSProviderSolver{},
		acmetest.SetResolvedZone(zone),
		acmetest.SetDNSName(zone),
		acmetest.SetStrict(true),
		acmetest.SetManifestPath("../testdata/dme"),
		acmetest.SetPropagationLimit(10*time.Second),
		acmetest.SetDNSServer(dns_server),
		acmetest.SetUseAuthoritative(false),
	)
	fixture.RunConformance(t)
}
