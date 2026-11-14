package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// testServerKey installs a throwaway server signing key for the whole test
// binary and returns it so fixtures can sign responses the client will accept.
func testServerKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serverSigningKey = base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	return key
}

func fixture(t *testing.T, s *Session, serverKey *ecdsa.PrivateKey) Response {
	t.Helper()
	secret, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	peer, e := ecdh.P256().NewPublicKey(s.public)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := secret.ECDH(peer)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	public := secret.PublicKey().Bytes()
	nonce, _ := random(32)
	hashed := sha256.Sum256(raw)
	defer clear(hashed[:])
	salt := append(append([]byte{}, s.nonce...), nonce...)
	info := append([]byte(protocol+"|"+s.request.DeviceID+"|"), s.public...)
	info = append(info, public...)
	info = append(info, s.nonce...)
	info = append(info, nonce...)
	info = append(info, be64(s.timestamp)...)
	key := hkdf64(hashed[:], salt, info)
	plain := []byte("{\"intervalSeconds\":42}")
	padding := 16 - len(plain)%16
	plain = append(plain, bytes.Repeat([]byte{byte(padding)}, padding)...)
	iv, _ := random(16)
	block, _ := aes.NewCipher(key[:32])
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	mac := hmac.New(sha256.New, key[32:])
	mac.Write([]byte("GoodGoodStudy.Config.v1|" + algorithm + "|"))
	mac.Write(iv)
	mac.Write(encrypted)
	signature, e := signTranscript(serverKey, responseTranscript(s.request.DeviceID, public, s.public, nonce, s.nonce, s.timestamp))
	if e != nil {
		t.Fatal(e)
	}
	return Response{3, protocol, base64.StdEncoding.EncodeToString(public), base64.StdEncoding.EncodeToString(nonce), s.timestamp, signature, Envelope{1, algorithm, base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(encrypted), base64.StdEncoding.EncodeToString(mac.Sum(nil))}}
}
func TestSessionAuthentication(t *testing.T) {
	serverKey := testServerKey(t)
	p, _ := newProfile()
	s, e := newSession(p)
	if e != nil {
		t.Fatal(e)
	}
	r := fixture(t, s, serverKey)
	c, e := s.decrypt(r)
	if e != nil || c.Interval != 42 {
		t.Fatal("round trip failed", e)
	}
	other, _ := newSession(p)
	if _, e = other.decrypt(r); e == nil {
		t.Fatal("cross-session replay accepted")
	}
	different := fixture(t, s, serverKey)
	if different.Public == r.Public || different.Nonce == r.Nonce {
		t.Fatal("ephemeral response reused")
	}
	for _, field := range []string{"mac", "iv", "nonce", "ciphertext", "signature"} {
		bad := r
		mutate := func(value string) string {
			b, _ := base64.StdEncoding.DecodeString(value)
			b[0] ^= 1
			return base64.StdEncoding.EncodeToString(b)
		}
		switch field {
		case "mac":
			bad.Payload.MAC = mutate(bad.Payload.MAC)
		case "iv":
			bad.Payload.IV = mutate(bad.Payload.IV)
		case "nonce":
			bad.Nonce = mutate(bad.Nonce)
		case "ciphertext":
			bad.Payload.Ciphertext = mutate(bad.Payload.Ciphertext)
		case "signature":
			bad.Signature = mutate(bad.Signature)
		}
		if _, e = s.decrypt(bad); e == nil {
			t.Fatalf("tampered %s accepted", field)
		}
	}
	// A response from a different server signing key must be rejected.
	forged := testServerKey(t)
	s2, _ := newSession(p)
	impostor := fixture(t, s2, forged)
	testServerKey(t) // rotate the trusted key away from the impostor's key
	if _, e = s2.decrypt(impostor); e == nil {
		t.Fatal("response signed by untrusted key accepted")
	}
}
func TestHKDFVector(t *testing.T) {
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	expected, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	actual := hkdf64(bytes.Repeat([]byte{11}, 22), salt, info)
	if !bytes.Equal(actual[:42], expected) {
		t.Fatal("RFC5869 vector mismatch")
	}
}
func TestConfigurationValidation(t *testing.T) {
	for _, value := range []string{"null", "{\"mail\":null}", "{\"intervalSeconds\":0}", "{\"batchSize\":0}", "{\"maxStorageMB\":1}", "{\"mail\":{\"enabled\":true}}", "{\"screenshotDirectory\":\"relative\"}"} {
		if _, e := decodeConfig([]byte(value)); e == nil {
			t.Fatalf("invalid configuration accepted: %s", value)
		}
	}
	c, e := decodeConfig([]byte("{}"))
	if e != nil || c.Directory != "" || c.Batch != 10 {
		t.Fatal("defaults invalid")
	}
}
func TestProfileDPAPI(t *testing.T) {
	p, e := newProfile()
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	if e = saveProfile(root, p); e != nil {
		t.Fatal(e)
	}
	loaded, e := loadProfile(root)
	if e != nil || loaded != p {
		t.Fatal("DPAPI roundtrip failed", e)
	}
	encrypted, _ := os.ReadFile(filepath.Join(root, "device-profile.dpapi"))
	if bytes.Contains(encrypted, []byte(p.Key)) {
		t.Fatal("credential stored as plaintext")
	}
	if _, e = os.Stat(filepath.Join(root, "config-key.dpapi")); !os.IsNotExist(e) {
		t.Fatal("unexpected persistent AES key")
	}
}
func TestProfileValidation(t *testing.T) {
	p, _ := newProfile()
	if validateProfile(p) != nil {
		t.Fatal("fresh profile rejected")
	}
	for _, bad := range []Profile{
		{p.DeviceID, ""},
		{p.DeviceID, "not-base64!!"},
		{p.DeviceID, base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{p.DeviceID, base64.StdEncoding.EncodeToString(make([]byte, 32))}, // zero scalar
		{"short", p.Key},
	} {
		if validateProfile(bad) == nil {
			t.Fatalf("invalid profile accepted: %+v", bad)
		}
	}
}
func TestPrivateExport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	if e := privateWrite(path, []byte("test")); e != nil {
		t.Fatal(e)
	}
	if privateWrite(path, []byte("overwrite")) == nil {
		t.Fatal("private export overwrite accepted")
	}
}
func TestArchives(t *testing.T) {
	root := t.TempDir()
	queue := filepath.Join(root, "queue")
	os.Mkdir(queue, 0700)
	for batch := 0; batch < 2; batch++ {
		var names []string
		for i := 0; i < 10; i++ {
			p := filepath.Join(root, unique(".png"))
			os.WriteFile(p, []byte("fake image"), 0600)
			names = append(names, p)
		}
		archive, e := archiveBatch(queue, names)
		if e != nil {
			t.Fatal(e)
		}
		z, e := zip.OpenReader(archive)
		if e != nil {
			t.Fatal(e)
		}
		if len(z.File) != 10 {
			t.Fatal("incomplete archive")
		}
		z.Close()
		for _, p := range names {
			if _, e = os.Stat(p); !os.IsNotExist(e) {
				t.Fatal("source not cleaned")
			}
		}
	}
	list, _ := images(queue, ".zip")
	if len(list) != 2 {
		t.Fatal("archive name collision")
	}
	survivor := filepath.Join(root, unique(".png"))
	os.WriteFile(survivor, []byte("keep"), 0600)
	if _, e := archiveBatch(queue, []string{survivor, filepath.Join(root, "missing.png")}); e == nil {
		t.Fatal("missing source accepted")
	}
	if _, e := os.Stat(survivor); e != nil {
		t.Fatal("original lost after failure")
	}
}
func TestURLPolicy(t *testing.T) {
	p, _ := newProfile()
	for _, address := range []string{"http://example.com", "https://a:b@example.com", "https://example.com/#fragment"} {
		if _, e := fetchConfig(address, p); e == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
}
func TestINIConversion(t *testing.T) {
	c, e := parseINI("senderMail=sender@example.com\nsmtpServer=smtp.example.com\ntokenCode=synthetic-test-only\ntoMail=recipient@example.com\ntimeInterval=3")
	if e != nil || c.Interval != 180 || !c.Mail.Enabled {
		t.Fatal("INI conversion failed", e)
	}
	b, _ := json.Marshal(c)
	if bytes.Contains(b, []byte("sessionKey")) {
		t.Fatal("unexpected key field")
	}
}
func TestNextBatch(t *testing.T) {
	const m = 1024 * 1024
	cases := []struct {
		sizes []int64
		batch int
		max   int64
		want  int
	}{
		{nil, 10, 9 * m, 0},
		{[]int64{m, m, m}, 10, 9 * m, 0},
		{[]int64{m, m, m, m, m, m, m, m, m, m, m, m}, 10, 100 * m, 10},
		{[]int64{4 * m, 4 * m, 4 * m}, 10, 9 * m, 2},
		{[]int64{3 * m, 3 * m, 3 * m, m}, 10, 9 * m, 3},
		{[]int64{20 * m, m}, 10, 9 * m, 1},
	}
	for _, c := range cases {
		if got := nextBatch(c.sizes, c.batch, c.max); got != c.want {
			t.Fatalf("nextBatch(%v) = %d, want %d", c.sizes, got, c.want)
		}
	}
}
func TestPruneCoversQueue(t *testing.T) {
	root := t.TempDir()
	captures, queue := filepath.Join(root, "captures"), filepath.Join(root, "pending")
	os.Mkdir(captures, 0700)
	os.Mkdir(queue, 0700)
	oldZip := filepath.Join(queue, "ggs-20200101T000000.000000001Z-a.zip")
	oversize := filepath.Join(queue, "ggs-20200101T000000.000000002Z-b.zip.oversize")
	midPNG := filepath.Join(captures, "ggs-20200101T000000.000000003Z-c.png")
	newPNG := filepath.Join(captures, "ggs-20200101T000000.000000004Z-d.png")
	foreign := filepath.Join(captures, "keep-me.txt")
	for _, p := range []string{oldZip, oversize, midPNG, newPNG} {
		os.WriteFile(p, make([]byte, 1000), 0600)
	}
	os.WriteFile(foreign, []byte("x"), 0600)
	prune(captures, 7, 1000000, queue)
	if _, e := os.Stat(oldZip); e != nil {
		t.Fatal("pruned while under limit")
	}
	prune(captures, 7, 2500, queue)
	for _, p := range []string{oldZip, oversize} {
		if _, e := os.Stat(p); !os.IsNotExist(e) {
			t.Fatal("oldest file kept", p)
		}
	}
	for _, p := range []string{midPNG, newPNG, foreign} {
		if _, e := os.Stat(p); e != nil {
			t.Fatal("newer or unmanaged file removed", p)
		}
	}
}
func TestQuarantine(t *testing.T) {
	root := t.TempDir()
	zip := filepath.Join(root, unique(".zip"))
	os.WriteFile(zip, []byte("zip"), 0600)
	if _, e := quarantine(zip); e != nil {
		t.Fatal(e)
	}
	if list, _ := images(root, ".zip"); len(list) != 0 {
		t.Fatal("oversize archive still queued")
	}
}
func TestSMTPPorts(t *testing.T) {
	for _, port := range []int{465, 994, 587} {
		data := fmt.Sprintf(`{"mail":{"enabled":true,"host":"smtp.example.test","port":%d,"enableSsl":true,"sender":"sender@example.test","recipient":"recipient@example.test","username":"synthetic-user","password":"synthetic-only"}}`, port)
		if c, e := decodeConfig([]byte(data)); e != nil || c.Mail.Port != port {
			t.Fatal("secure SMTP port rejected", port, e)
		}
	}
	ini := "senderMail=sender@example.test\nsmtpServer=smtp.163.com\ntokenCode=synthetic-only\ntoMail=recipient@example.test\ntimeInterval=2"
	if c, e := parseINI(ini); e != nil || c.Mail.Port != 465 {
		t.Fatal("163 INI should use implicit TLS port 465", e)
	}
	if c, e := parseINI(ini + "\nsmtpPort=994"); e != nil || c.Mail.Port != 994 {
		t.Fatal("explicit smtpPort ignored", e)
	}
}
