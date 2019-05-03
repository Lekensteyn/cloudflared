// Adapted from https://github.com/cloudflare/tls-tris
// _dev/tris-testclient/esni_query.go
package carrier

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func makeDoTQuery(dnsName string) ([]byte, error) {
	query := dnsmessage.Message{
		Header: dnsmessage.Header{
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(dnsName),
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	req, err := query.Pack()
	if err != nil {
		return nil, err
	}
	l := len(req)
	req = append([]byte{
		uint8(l >> 8),
		uint8(l),
	}, req...)
	return req, nil
}

func parseTXTResponse(buf []byte, wantName string) (string, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(buf)
	if err != nil {
		return "", err
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return "", fmt.Errorf("DNS query failed, rcode=%s", hdr.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", err
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return "", err
		}
		if h.Type != dnsmessage.TypeTXT || h.Class != dnsmessage.ClassINET {
			continue
		}
		if !strings.EqualFold(h.Name.String(), wantName) {
			if err := p.SkipAnswer(); err != nil {
				return "", err
			}
		}
		r, err := p.TXTResource()
		if err != nil {
			return "", err
		}
		return r.TXT[0], nil
	}
	return "", errors.New("No TXT record found")
}

// for debugging in Wireshark
func enableKeyLog(tlsConfig *tls.Config) {
	keylog_file := os.Getenv("SSLKEYLOGFILE")
	if keylog_file != "" {
		keylog_writer, err := os.OpenFile(keylog_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Cannot open keylog file: %v", err)
		}
		tlsConfig.KeyLogWriter = keylog_writer
		log.Println("Enabled keylog")
	}
}

// returns the ESNIKeys for the hostname. If ipOut is not nil, an additional A
// query will be attempted to get the IPv4 address.
func QueryESNIKeysForHost(hostname string, ipOut *string) ([]byte, error) {
	esniDnsName := "_esni." + hostname + "."
	query, err := makeDoTQuery(esniDnsName)
	if err != nil {
		return nil, fmt.Errorf("Building DNS query TXT failed: %s", err)
	}
	tlsConfig := &tls.Config{}
	enableKeyLog(tlsConfig)
	c, err := tls.Dial("tcp", "1.1.1.1:853", tlsConfig)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// Send DNS query (TXT)
	n, err := c.Write(query)
	if err != nil || n != len(query) {
		return nil, fmt.Errorf("Failed to write query: %s", err)
	}

	// Read DNS response
	buf := make([]byte, 4096)
	n, err = c.Read(buf)
	if n < 2 && err != nil {
		return nil, fmt.Errorf("Cannot read response: %s", err)
	}
	txt, err := parseTXTResponse(buf[2:n], esniDnsName)
	if err != nil {
		return nil, fmt.Errorf("Cannot process TXT record: %s", err)
	}
	esniKeysBytes, err := base64.StdEncoding.DecodeString(txt)
	if err != nil {
		return nil, err
	}

	if ipOut != nil {
		queryA, err := makeDoTQueryA(hostname + ".")
		if err != nil {
			return nil, fmt.Errorf("Building DNS query A failed: %s", err)
		}

		// Send DNS query (A)
		n, err := c.Write(queryA)
		if err != nil || n != len(queryA) {
			return nil, fmt.Errorf("Failed to write query A: %s", err)
		}

		// Read DNS response
		n, err = c.Read(buf)
		if n < 2 && err != nil {
			return nil, fmt.Errorf("Cannot read response A: %s", err)
		}
		ipv4, err := parseAResponse(buf[2:n], hostname+".")
		if err != nil {
			return nil, fmt.Errorf("Cannot process A record: %s", err)
		}
		*ipOut = ipv4
	}

	return esniKeysBytes, nil
}

func makeDoTQueryA(dnsName string) ([]byte, error) {
	query := dnsmessage.Message{
		Header: dnsmessage.Header{
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(dnsName),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	req, err := query.Pack()
	if err != nil {
		return nil, err
	}
	l := len(req)
	req = append([]byte{
		uint8(l >> 8),
		uint8(l),
	}, req...)
	return req, nil
}

// Returns an IPv4 address if any
func parseAResponse(buf []byte, wantName string) (string, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(buf)
	if err != nil {
		return "", err
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return "", fmt.Errorf("DNS query failed, rcode=%s", hdr.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", err
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return "", err
		}
		if h.Type != dnsmessage.TypeA || h.Class != dnsmessage.ClassINET {
			continue
		}
		if !strings.EqualFold(h.Name.String(), wantName) {
			if err := p.SkipAnswer(); err != nil {
				return "", err
			}
		}
		r, err := p.AResource()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d.%d.%d.%d", r.A[0], r.A[1], r.A[2], r.A[2]), nil
	}
	return "", errors.New("No TXT record found")
}
