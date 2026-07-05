package config

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
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

	transport := client.Transport.(*http.Transport)
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

	transport := client.Transport.(*http.Transport)
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

	transport := client.Transport.(*http.Transport)
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

	transport := client.Transport.(*http.Transport)
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
