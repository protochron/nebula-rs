// Command gen-fixtures generates real, byte-for-byte-correct Nebula v2 CA
// and host certificates using the actual slackhq/nebula v1.10.3 cert
// package, for use as ground-truth fixtures in nebula-protocol's Rust
// tests. Not part of the crate's runtime — run once (or whenever the
// fixtures need regenerating) via `go run .`.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// Fixed timestamps so regenerating fixtures produces stable, reviewable
// diffs instead of churning every run.
var (
	notBefore       = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter        = notBefore.Add(2 * 365 * 24 * time.Hour)
	expiredNotAfter = notBefore.Add(1 * time.Hour)
)

type fixtureManifest struct {
	CA      certInfo `json:"ca"`
	HostA   certInfo `json:"host_a"`
	HostB   certInfo `json:"host_b"`
	Expired certInfo `json:"expired"`
}

type certInfo struct {
	Name        string   `json:"name"`
	Groups      []string `json:"groups"`
	Networks    []string `json:"networks"`
	IsCA        bool     `json:"is_ca"`
	NotBefore   int64    `json:"not_before"`
	NotAfter    int64    `json:"not_after"`
	Issuer      string   `json:"issuer"`
	Curve       string   `json:"curve"`
	Fingerprint string   `json:"fingerprint"`
}

func x25519Keypair() (pub, priv []byte) {
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		panic(err)
	}
	var err error
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func toInfo(c nebulacert.Certificate) certInfo {
	fp, err := c.Fingerprint()
	if err != nil {
		panic(err)
	}
	nets := make([]string, len(c.Networks()))
	for i, n := range c.Networks() {
		nets[i] = n.String()
	}
	return certInfo{
		Name:        c.Name(),
		Groups:      c.Groups(),
		Networks:    nets,
		IsCA:        c.IsCA(),
		NotBefore:   c.NotBefore().Unix(),
		NotAfter:    c.NotAfter().Unix(),
		Issuer:      c.Issuer(),
		Curve:       c.Curve().String(),
		Fingerprint: fp,
	}
}

func writeFile(dir, name string, b []byte) {
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		panic(err)
	}
}

func signHost(name, network string, ca nebulacert.Certificate, caPriv []byte, notAfter time.Time) (nebulacert.Certificate, []byte) {
	pub, priv := x25519Keypair()
	tbs := &nebulacert.TBSCertificate{
		Version:   nebulacert.Version2,
		Name:      name,
		Networks:  []netip.Prefix{mustPrefix(network)},
		Groups:    []string{"test"},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		PublicKey: pub,
		Curve:     nebulacert.Curve_CURVE25519,
	}
	signed, err := tbs.Sign(ca, nebulacert.Curve_CURVE25519, caPriv)
	if err != nil {
		panic(fmt.Errorf("sign %s: %w", name, err))
	}
	return signed, priv
}

func main() {
	outDir := "../../tests/fixtures"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}

	// --- CA ---
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	caTBS := &nebulacert.TBSCertificate{
		Version:   nebulacert.Version2,
		Name:      "nebula-protocol test CA",
		Networks:  []netip.Prefix{mustPrefix("10.100.0.0/16")},
		IsCA:      true,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		PublicKey: caPub,
		Curve:     nebulacert.Curve_CURVE25519,
	}
	caCert, err := caTBS.Sign(nil, nebulacert.Curve_CURVE25519, caPriv)
	if err != nil {
		panic(fmt.Errorf("sign ca: %w", err))
	}
	caCertPEM, err := caCert.MarshalPEM()
	if err != nil {
		panic(err)
	}
	caKeyPEM := nebulacert.MarshalSigningPrivateKeyToPEM(nebulacert.Curve_CURVE25519, caPriv)
	writeFile(outDir, "ca.crt", caCertPEM)
	writeFile(outDir, "ca.key", caKeyPEM)

	// --- host-a / host-b ---
	hostACert, hostAPriv := signHost("host-a", "10.100.0.1/16", caCert, caPriv, notAfter)
	hostACertPEM, err := hostACert.MarshalPEM()
	if err != nil {
		panic(err)
	}
	writeFile(outDir, "host-a.crt", hostACertPEM)
	writeFile(outDir, "host-a.key", nebulacert.MarshalPrivateKeyToPEM(nebulacert.Curve_CURVE25519, hostAPriv))

	hostBCert, hostBPriv := signHost("host-b", "10.100.0.2/16", caCert, caPriv, notAfter)
	hostBCertPEM, err := hostBCert.MarshalPEM()
	if err != nil {
		panic(err)
	}
	writeFile(outDir, "host-b.crt", hostBCertPEM)
	writeFile(outDir, "host-b.key", nebulacert.MarshalPrivateKeyToPEM(nebulacert.Curve_CURVE25519, hostBPriv))

	// --- tampered (host-a with the last signature byte flipped, for negative signature tests) ---
	tamperedDER, err := hostACert.Marshal()
	if err != nil {
		panic(err)
	}
	tamperedDER = append([]byte(nil), tamperedDER...)
	tamperedDER[len(tamperedDER)-1] ^= 0xFF
	writeFile(outDir, "host-a-tampered.crt", pem.EncodeToMemory(&pem.Block{
		Type:  nebulacert.CertificateV2Banner,
		Bytes: tamperedDER,
	}))

	// --- expired ---
	expiredCert, expiredPriv := signHost("expired-host", "10.100.0.3/16", caCert, caPriv, expiredNotAfter)
	expiredCertPEM, err := expiredCert.MarshalPEM()
	if err != nil {
		panic(err)
	}
	writeFile(outDir, "expired.crt", expiredCertPEM)
	writeFile(outDir, "expired.key", nebulacert.MarshalPrivateKeyToPEM(nebulacert.Curve_CURVE25519, expiredPriv))

	// --- manifest ---
	manifest := fixtureManifest{
		CA:      toInfo(caCert),
		HostA:   toInfo(hostACert),
		HostB:   toInfo(hostBCert),
		Expired: toInfo(expiredCert),
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		panic(err)
	}
	writeFile(outDir, "fixtures.json", manifestJSON)

	fmt.Println("wrote fixtures to", outDir)
}
