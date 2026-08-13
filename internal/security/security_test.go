package security

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestVersionedAdversarialCorpusZeroTolerance(t *testing.T) {
	corpus, err := LoadCorpus("testdata/m7-adversarial-corpus.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := RunCorpus(context.Background(), corpus)
	if err != nil || len(findings) != len(corpus.Cases) {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
	for index, finding := range findings {
		if finding.Outcome != "blocked" || !finding.Recorded || !corpus.Cases[index].PreviouslySuccessful {
			t.Fatalf("case=%#v finding=%#v", corpus.Cases[index], finding)
		}
	}
}

func TestEgressProtocolDNSIPRedirectAndBounds(t *testing.T) {
	resolver := staticResolver{addresses: map[string][]net.IPAddr{
		"public.example":   {{IP: net.ParseIP("8.8.8.8")}},
		"private.example":  {{IP: net.ParseIP("10.0.0.1")}},
		"metadata.example": {{IP: net.ParseIP("169.254.169.254")}},
	}}
	guard, _ := NewEgressGuard(EgressPolicy{AllowedHosts: map[string]struct{}{"public.example": {}, "private.example": {}, "metadata.example": {}}, MaximumBytes: 4096, MaximumDuration: 2 * time.Second, AllowRedirects: true}, resolver)
	destination, err := guard.Resolve(context.Background(), "https://public.example/path")
	if err != nil || guard.MaximumBytes() != 4096 || guard.MaximumDuration() != 2*time.Second {
		t.Fatalf("destination=%#v err=%v", destination, err)
	}
	for _, raw := range []string{"http://public.example", "https://user:password@public.example", "https://private.example", "https://metadata.example", "https://unlisted.example"} {
		if _, err := guard.Resolve(context.Background(), raw); err == nil {
			t.Fatalf("unsafe destination accepted: %s", raw)
		}
	}
	if _, err := guard.ValidateRedirect(context.Background(), destination, "https://metadata.example/latest"); err == nil {
		t.Fatal("unsafe redirect accepted")
	}
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if body, err := guard.ReadResponse(bounded, bytes.NewReader(make([]byte, 4096))); err != nil || len(body) != 4096 {
		t.Fatalf("bounded body=%d err=%v", len(body), err)
	}
	if _, err := guard.ReadResponse(bounded, bytes.NewReader(make([]byte, 4097))); err == nil {
		t.Fatal("oversized response accepted")
	}
	if _, err := guard.ReadResponse(context.Background(), bytes.NewReader(nil)); err == nil {
		t.Fatal("unbounded response context accepted")
	}
}
