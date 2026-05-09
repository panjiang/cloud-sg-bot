package main

import "testing"

func TestExtractPublicIPv4(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain ip", input: "8.8.8.8", want: "8.8.8.8"},
		{name: "prefixed ip", input: "Client IP: 61.48.63.203", want: "61.48.63.203"},
		{name: "skips private then public", input: "10.0.0.1 1.1.1.1", want: "1.1.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := ExtractPublicIPv4(tt.input)
			if err != nil {
				t.Fatalf("ExtractPublicIPv4() error = %v", err)
			}
			if ip.String() != tt.want {
				t.Fatalf("IP = %q, want %q", ip.String(), tt.want)
			}
		})
	}
}

func TestExtractPublicIPv4RejectsNonPublic(t *testing.T) {
	for _, input := range []string{"", "hello", "10.0.0.1", "127.0.0.1", "169.254.1.1", "999.999.999.999"} {
		t.Run(input, func(t *testing.T) {
			if _, err := ExtractPublicIPv4(input); err == nil {
				t.Fatal("ExtractPublicIPv4() expected error")
			}
		})
	}
}
