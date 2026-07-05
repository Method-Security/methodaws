package config

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"golang.org/x/net/proxy"
)

type proxyContextKey struct{}

// ProxyConfig captures global proxy settings for AWS SDK HTTP traffic.
type ProxyConfig struct {
	HTTPProxy  string
	SOCKSProxy string
}

// SetProxyConfig stores proxy settings on the command context for paths that
// create their own AWS config later in execution.
func SetProxyConfig(ctx context.Context, proxyConfig ProxyConfig) context.Context {
	return context.WithValue(ctx, proxyContextKey{}, proxyConfig)
}

// ProxyConfigFromContext returns proxy settings from context, if present.
func ProxyConfigFromContext(ctx context.Context) ProxyConfig {
	if proxyConfig, ok := ctx.Value(proxyContextKey{}).(ProxyConfig); ok {
		return proxyConfig
	}
	return ProxyConfig{}
}

// AWSLoadOptionsForProxy returns AWS SDK config load options for proxy settings.
func AWSLoadOptionsForProxy(proxyConfig ProxyConfig) ([]awsconfig.LoadOptionsFunc, error) {
	client, err := HTTPClientForProxy(proxyConfig)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, nil
	}
	return []awsconfig.LoadOptionsFunc{awsconfig.WithHTTPClient(client)}, nil
}

// AWSLoadOptionsFromContext returns AWS SDK config load options from context.
func AWSLoadOptionsFromContext(ctx context.Context) ([]awsconfig.LoadOptionsFunc, error) {
	return AWSLoadOptionsForProxy(ProxyConfigFromContext(ctx))
}

// HTTPClientForProxy creates an HTTP client configured for HTTP(S) or SOCKS5 proxies.
// If both proxy types are set, SOCKS5 takes precedence.
func HTTPClientForProxy(proxyConfig ProxyConfig) (*http.Client, error) {
	if proxyConfig.HTTPProxy == "" && proxyConfig.SOCKSProxy == "" {
		return nil, nil
	}

	transport := defaultProxyTransport()
	if proxyConfig.SOCKSProxy != "" {
		if err := configureSOCKSProxy(transport, proxyConfig.SOCKSProxy); err != nil {
			return nil, err
		}
		return &http.Client{Transport: transport}, nil
	}

	if err := configureHTTPProxy(transport, proxyConfig.HTTPProxy); err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport}, nil
}

func defaultProxyTransport() *http.Transport {
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		return defaultTransport.Clone()
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

func configureHTTPProxy(transport *http.Transport, rawProxyURL string) error {
	proxyURL, err := url.Parse(rawProxyURL)
	if err != nil {
		return fmt.Errorf("invalid HTTP proxy URL: %w", err)
	}
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return fmt.Errorf("invalid HTTP proxy scheme %q: expected http or https", proxyURL.Scheme)
	}
	if proxyURL.Host == "" {
		return fmt.Errorf("invalid HTTP proxy URL: missing host")
	}

	transport.Proxy = http.ProxyURL(proxyURL)
	return nil
}

func configureSOCKSProxy(transport *http.Transport, rawProxyURL string) error {
	proxyURL, err := url.Parse(rawProxyURL)
	if err != nil {
		return fmt.Errorf("invalid SOCKS proxy URL: %w", err)
	}
	if proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
		return fmt.Errorf("invalid SOCKS proxy scheme %q: expected socks5 or socks5h", proxyURL.Scheme)
	}
	if proxyURL.Host == "" {
		return fmt.Errorf("invalid SOCKS proxy URL: missing host")
	}

	dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS proxy dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return fmt.Errorf("SOCKS proxy dialer does not support context-aware dialing")
	}

	transport.Proxy = noHTTPProxy
	transport.DialContext = contextDialer.DialContext
	return nil
}

func noHTTPProxy(*http.Request) (*url.URL, error) {
	return nil, nil
}
