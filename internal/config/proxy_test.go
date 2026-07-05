package config

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

func TestHTTPClientForProxyReturnsNilWithoutProxy(t *testing.T) {
	client, err := HTTPClientForProxy(ProxyConfig{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if client != nil {
		t.Fatal("expected no HTTP client when no proxy is configured")
	}
}

func TestHTTPClientForProxyConfiguresHTTPProxy(t *testing.T) {
	client, err := HTTPClientForProxy(ProxyConfig{HTTPProxy: "http://user:pass@127.0.0.1:8080"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	transport := client.GetTransport()
	requestURL, err := url.Parse("https://sts.amazonaws.com")
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	proxyURL, err := transport.Proxy(&http.Request{URL: requestURL})
	if err != nil {
		t.Fatalf("expected proxy lookup to succeed: %v", err)
	}
	if proxyURL.String() != "http://user:pass@127.0.0.1:8080" {
		t.Fatalf("expected configured HTTP proxy, got %s", proxyURL.String())
	}
}

func TestHTTPClientForProxyConfiguresSOCKSProxy(t *testing.T) {
	client, err := HTTPClientForProxy(ProxyConfig{SOCKSProxy: "socks5://127.0.0.1:1080"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	transport := client.GetTransport()
	if transport.DialContext == nil {
		t.Fatal("expected SOCKS proxy to configure DialContext")
	}

	requestURL, err := url.Parse("https://sts.amazonaws.com")
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	proxyURL, err := transport.Proxy(&http.Request{URL: requestURL})
	if err != nil {
		t.Fatalf("expected proxy lookup to succeed: %v", err)
	}
	if proxyURL != nil {
		t.Fatalf("expected SOCKS proxy to disable HTTP proxy lookup, got %s", proxyURL.String())
	}
}

func TestHTTPClientForProxyPrefersSOCKSProxy(t *testing.T) {
	client, err := HTTPClientForProxy(ProxyConfig{
		HTTPProxy:  "http://127.0.0.1:8080",
		SOCKSProxy: "socks5://127.0.0.1:1080",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	transport := client.GetTransport()
	requestURL, err := url.Parse("https://sts.amazonaws.com")
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	proxyURL, err := transport.Proxy(&http.Request{URL: requestURL})
	if err != nil {
		t.Fatalf("expected proxy lookup to succeed: %v", err)
	}
	if proxyURL != nil {
		t.Fatalf("expected SOCKS proxy to take precedence, got HTTP proxy %s", proxyURL.String())
	}
}

func TestHTTPClientForProxyRejectsInvalidSchemes(t *testing.T) {
	_, err := HTTPClientForProxy(ProxyConfig{HTTPProxy: "socks5://127.0.0.1:1080"})
	if err == nil {
		t.Fatal("expected invalid HTTP proxy scheme to fail")
	}

	_, err = HTTPClientForProxy(ProxyConfig{SOCKSProxy: "http://127.0.0.1:8080"})
	if err == nil {
		t.Fatal("expected invalid SOCKS proxy scheme to fail")
	}
}

func TestSOCKSProxyDialContextHonorsCanceledContext(t *testing.T) {
	client, err := HTTPClientForProxy(ProxyConfig{SOCKSProxy: "socks5://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	transport := client.GetTransport()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = transport.DialContext(ctx, "tcp", "sts.amazonaws.com:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled context error, got %v", err)
	}
}

func TestAWSLoadOptionsFromContext(t *testing.T) {
	ctx := SetProxyConfig(context.Background(), ProxyConfig{HTTPProxy: "http://127.0.0.1:8080"})

	loadOptions, err := AWSLoadOptionsFromContext(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(loadOptions) != 1 {
		t.Fatalf("expected one load option, got %d", len(loadOptions))
	}
}

func TestProxyHTTPClientIsAWSBuildableClient(t *testing.T) {
	client, err := HTTPClientForProxy(ProxyConfig{HTTPProxy: "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if _, ok := any(client).(*awshttp.BuildableClient); !ok {
		t.Fatalf("expected proxy client to be an AWS buildable client, got %T", client)
	}
}

func TestAWSLoadOptionsWithProxySupportsCustomCABundle(t *testing.T) {
	caBundlePath := writeTestCABundle(t)
	t.Setenv("AWS_CA_BUNDLE", caBundlePath)

	loadOptions, err := AWSLoadOptionsForProxy(ProxyConfig{HTTPProxy: "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	loadOptions = append(loadOptions,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		t.Fatalf("expected AWS config load with proxy and custom CA bundle to succeed, got %v", err)
	}
	if _, ok := cfg.HTTPClient.(*awshttp.BuildableClient); !ok {
		t.Fatalf("expected custom CA bundle to preserve buildable client, got %T", cfg.HTTPClient)
	}
}

func TestProxyHTTPClientPreservesAWSRedirectPolicy(t *testing.T) {
	client, err := HTTPClientForProxy(ProxyConfig{HTTPProxy: "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	client = client.WithTransportOptions(func(tr *http.Transport) {
		tr.Proxy = nil
		tr.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go func() {
				defer func() {
					_ = serverConn.Close()
				}()

				req, err := http.ReadRequest(bufio.NewReader(serverConn))
				if err == nil {
					_ = req.Body.Close()
				}
				_, _ = serverConn.Write([]byte("HTTP/1.1 302 Found\r\nLocation: http://redirected.example/\r\nContent-Length: 0\r\n\r\n"))
			}()
			return clientConn, nil
		}
	})

	req, err := http.NewRequest(http.MethodGet, "http://aws.example/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected request to succeed, got %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected AWS redirect policy not to follow 302, got %d", resp.StatusCode)
	}
}

func writeTestCABundle(t *testing.T) string {
	t.Helper()

	certDER := createSelfSignedCertificate(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if certPEM == nil {
		t.Fatal("failed to encode certificate PEM")
	}

	if _, err := x509.ParseCertificate(certDER); err != nil {
		t.Fatalf("test certificate is invalid: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ca-bundle.pem")
	if err := os.WriteFile(path, certPEM, 0600); err != nil {
		t.Fatalf("failed to write CA bundle: %v", err)
	}
	return path
}

func createSelfSignedCertificate(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "methodaws proxy test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to generate test certificate: %v", err)
	}
	return certDER
}
