package carrier

import (
	"crypto/tls"
	"fmt"
)

// Enables ESNI support.
// Returns suitable TLS config and the IPv4 address on success.
func createTLSClientConfig(hostname string) (*tls.Config, string, error) {
	// XXX This is just for demonstration purposes. It is not efficient as
	// it always creates a TLS connection for every single DNS request.
	// Consider using the existing DoH client (tunneldns).
	var ipAddr string
	esniKeysBytes, err := QueryESNIKeysForHost(hostname, &ipAddr)
	if err != nil {
		return nil, "", fmt.Errorf("Failed to retrieve ESNI for host: %s", err)
	}
	// XXX the spec recommends falling back to cleartext DNS if ESNI fails.
	// Right now the TLS client will always fail when a bad key is in use.
	// Maybe provide a configuration option (esni=optional/required)?
	esniKeys, err := tls.ParseESNIKeys(esniKeysBytes)
	if esniKeys == nil {
		return nil, "", fmt.Errorf("Failed to process ESNI response for host: %s", err)
	}

	tlsClientConfig := &tls.Config{
		ServerName:     hostname,
		ClientESNIKeys: esniKeys,
	}
	return tlsClientConfig, ipAddr, nil
}
