package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, s *Session) Response {
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
	key := hkdf64(hashed[:], salt, info)
	defer clear(key)
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
	return Response{2, protocol, base64.StdEncoding.EncodeToString(public), base64.StdEncoding.EncodeToString(nonce), Envelope{1, algorithm, base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(encrypted), base64.StdEncoding.EncodeToString(mac.Sum(nil))}}
}
func TestSessionAuthentication(t *testing.T) {
	p, _ := newProfile()
	s, e := newSession(p.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	r := fixture(t, s)
	c, e := s.decrypt(r)
	if e != nil || c.Interval != 42 {
		t.Fatal("round trip failed", e)
	}
	other, _ := newSession(p.DeviceID)
	if _, e = other.decrypt(r); e == nil {
		t.Fatal("cross-session replay accepted")
	}
	different := fixture(t, s)
	if different.Public == r.Public || different.Nonce == r.Nonce {
		t.Fatal("ephemeral response reused")
	}
	for _, field := range []string{"mac", "iv", "nonce", "ciphertext"} {
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
		}
		if _, e = s.decrypt(bad); e == nil {
			t.Fatalf("tampered %s accepted", field)
		}
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
	if bytes.Contains(encrypted, []byte(p.Token)) {
		t.Fatal("credential stored as plaintext")
	}
	if _, e = os.Stat(filepath.Join(root, "config-key.dpapi")); !os.IsNotExist(e) {
		t.Fatal("unexpected persistent AES key")
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
