package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"
)

var ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

type IPFetcher struct {
	client *http.Client
}

func NewIPFetcher(timeout time.Duration) *IPFetcher {
	return &IPFetcher{
		client: &http.Client{Timeout: timeout},
	}
}

func (f *IPFetcher) FetchIPv4(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build ip request: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch ip source: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("ip source returned status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("read ip source: %w", err)
	}
	ip, err := ExtractPublicIPv4(string(body))
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

func ExtractPublicIPv4(input string) (net.IP, error) {
	matches := ipv4Pattern.FindAllString(input, -1)
	for _, match := range matches {
		ip := net.ParseIP(match)
		if ip == nil {
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}
		if isPublicIPv4(ip) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no public IPv4 address found")
}

func isPublicIPv4(ip net.IP) bool {
	if ip == nil || ip.To4() == nil {
		return false
	}
	return !ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}
