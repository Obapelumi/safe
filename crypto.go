package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const hostsMarker = "# >>> safe blocklist >>>"

// failOnRealRun guards destructive steps: in dry-run we must never touch the
// system. cmd() returns a no-op when apply is false.
type runner struct {
	apply bool
}

func (r runner) cmd(name string, args ...string) error {
	line := strings.Join(append([]string{name}, args...), " ")
	if !r.apply {
		fmt.Printf("  [dry-run] sudo %s\n", line)
		return nil
	}
	fmt.Printf("  [run] sudo %s\n", line)
	c := execCommand("sudo", append([]string{name}, args...)...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func (r runner) shell(script string) error {
	if !r.apply {
		fmt.Printf("  [dry-run] sudo sh -c %q\n", script)
		return nil
	}
	fmt.Printf("  [run] sudo sh -c %q\n", script)
	c := execCommand("sudo", "sh", "-c", script)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func loadDomains(assetPath string) ([]string, error) {
	f, err := os.Open(assetPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var domains []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		token := fields[len(fields)-1]
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" || seen[token] {
			continue
		}
		seen[token] = true
		domains = append(domains, token)
	}
	return domains, sc.Err()
}

// renderHostsBlock returns the managed block that will be appended to /etc/hosts.
func renderHostsBlock(domains []string) string {
	var b strings.Builder
	b.WriteString(hostsMarker + "\n")
	b.WriteString("# Managed by safe. Removed by the rollback bundle only.\n")
	for _, d := range domains {
		b.WriteString("0.0.0.0 " + d + "\n")
		if !strings.HasPrefix(d, "www.") {
			b.WriteString("0.0.0.0 www." + d + "\n")
		}
	}
	b.WriteString("# <<< safe blocklist <<<\n")
	return b.String()
}

func randomSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func deriveKey(secretHex string) ([]byte, error) {
	raw, err := hex.DecodeString(secretHex)
	if err != nil || len(raw) < 16 {
		return nil, fmt.Errorf("secret must be at least 16 hex-encoded bytes")
	}
	// SHA-256 to normalise to a 32-byte AES key.
	sum := sha256Sum(raw)
	return sum, nil
}

func encrypt(secretHex string, plaintext []byte) ([]byte, error) {
	key, err := deriveKey(secretHex)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := append(nonce, ct...)
	return []byte(base64.StdEncoding.EncodeToString(out)), nil
}

func decrypt(secretHex string, b64 []byte) ([]byte, error) {
	key, err := deriveKey(secretHex)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func writeIfChanged(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
