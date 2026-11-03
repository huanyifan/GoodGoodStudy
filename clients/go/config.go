package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const endpoint = "https://yifan.im/tools/goodgoodstudy/config.json"
const protocol = "GoodGoodStudy.Config.ECDH-P256.HKDF-SHA256.v2"
const algorithm = "AES-256-CBC+HMAC-SHA256"

var invalid = errors.New("configuration or device credential invalid")

type Profile struct {
	DeviceID string `json:"deviceId"`
	Token    string `json:"accessToken"`
}
type MailConfig struct {
	Enabled   bool   `json:"enabled"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	TLS       bool   `json:"enableSsl"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}
type Config struct {
	Interval  int        `json:"intervalSeconds"`
	Batch     int        `json:"batchSize"`
	Directory string     `json:"screenshotDirectory"`
	Retention int        `json:"retentionDays"`
	Storage   int        `json:"maxStorageMB"`
	Mail      MailConfig `json:"mail"`
}

func decodeConfig(b []byte) (Config, error) {
	c := Config{Interval: 180, Batch: 10, Retention: 7, Storage: 512, Mail: MailConfig{Port: 587, TLS: true}}
	var shape map[string]json.RawMessage
	if len(b) > 65536 || json.Unmarshal(b, &shape) != nil || shape == nil || bytes.Equal(bytes.TrimSpace(shape["mail"]), []byte("null")) || json.Unmarshal(b, &c) != nil {
		return c, invalid
	}
	if c.Interval < 1 || c.Interval > 86400 || c.Batch < 1 || c.Batch > 100 || c.Retention < 1 || c.Retention > 365 || c.Storage < 16 || c.Storage > 8192 {
		return c, invalid
	}
	if c.Directory != "" && !filepath.IsAbs(c.Directory) {
		return c, invalid
	}
	if c.Mail.Enabled {
		from, e1 := mail.ParseAddress(c.Mail.Sender)
		to, e2 := mail.ParseAddress(c.Mail.Recipient)
		if e1 != nil || e2 != nil || c.Mail.Host == "" || c.Mail.Port < 1 || c.Mail.Port > 65535 || !c.Mail.TLS || c.Mail.Port == 465 || c.Mail.Username == "" || c.Mail.Password == "" {
			return c, invalid
		}
		c.Mail.Sender = from.Address
		c.Mail.Recipient = to.Address
	}
	return c, nil
}
func validateProfile(p Profile) error {
	b, e := base64.StdEncoding.Strict().DecodeString(p.Token)
	defer clear(b)
	if e != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != p.Token || len(p.DeviceID) != 36 {
		return invalid
	}
	return nil
}
func random(n int) ([]byte, error) { b := make([]byte, n); _, e := rand.Read(b); return b, e }
func newProfile() (Profile, error) {
	b, e := random(16)
	if e != nil {
		return Profile{}, e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	token, e := random(32)
	if e != nil {
		return Profile{}, e
	}
	defer clear(token)
	id := fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
	return Profile{id, base64.StdEncoding.EncodeToString(token)}, nil
}

type Handshake struct {
	Version  int    `json:"version"`
	DeviceID string `json:"deviceId"`
	Public   string `json:"clientPublicKey"`
	Nonce    string `json:"clientNonce"`
}
type Envelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
	MAC        string `json:"mac"`
}
type Response struct {
	Version  int      `json:"version"`
	Protocol string   `json:"keyAgreement"`
	Public   string   `json:"serverPublicKey"`
	Nonce    string   `json:"serverNonce"`
	Payload  Envelope `json:"payload"`
}
type Session struct {
	private       *ecdh.PrivateKey
	request       Handshake
	public, nonce []byte
}

func newSession(id string) (*Session, error) {
	key, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	nonce, e := random(32)
	if e != nil {
		return nil, e
	}
	pub := key.PublicKey().Bytes()
	return &Session{key, Handshake{2, id, base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(nonce)}, pub, nonce}, nil
}
func hkdf64(secret, salt, info []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(secret)
	prk := h.Sum(nil)
	defer clear(prk)
	h = hmac.New(sha256.New, prk)
	h.Write(info)
	h.Write([]byte{1})
	first := h.Sum(nil)
	defer clear(first)
	h = hmac.New(sha256.New, prk)
	h.Write(first)
	h.Write(info)
	h.Write([]byte{2})
	second := h.Sum(nil)
	defer clear(second)
	out := make([]byte, 64)
	copy(out, first)
	copy(out[32:], second)
	return out
}
func (s *Session) decrypt(r Response) (Config, error) {
	if r.Version != 2 || r.Protocol != protocol || r.Payload.Version != 1 || r.Payload.Algorithm != algorithm {
		return Config{}, invalid
	}
	pub, e := base64.StdEncoding.DecodeString(r.Public)
	if e != nil || len(pub) != 65 {
		return Config{}, invalid
	}
	nonce, e := base64.StdEncoding.DecodeString(r.Nonce)
	if e != nil || len(nonce) != 32 {
		return Config{}, invalid
	}
	peer, e := ecdh.P256().NewPublicKey(pub)
	if e != nil {
		return Config{}, invalid
	}
	raw, e := s.private.ECDH(peer)
	if e != nil {
		return Config{}, invalid
	}
	defer clear(raw)
	hashed := sha256.Sum256(raw)
	defer clear(hashed[:])
	salt := append(append([]byte{}, s.nonce...), nonce...)
	info := append([]byte(protocol+"|"+s.request.DeviceID+"|"), s.public...)
	info = append(info, pub...)
	info = append(info, s.nonce...)
	info = append(info, nonce...)
	key := hkdf64(hashed[:], salt, info)
	defer clear(key)
	iv, e := base64.StdEncoding.DecodeString(r.Payload.IV)
	if e != nil || len(iv) != 16 {
		return Config{}, invalid
	}
	ciphertext, e := base64.StdEncoding.DecodeString(r.Payload.Ciphertext)
	if e != nil || len(ciphertext) == 0 || len(ciphertext)%16 != 0 || len(ciphertext) > 65552 {
		return Config{}, invalid
	}
	tag, e := base64.StdEncoding.DecodeString(r.Payload.MAC)
	if e != nil || len(tag) != 32 {
		return Config{}, invalid
	}
	mac := hmac.New(sha256.New, key[32:])
	mac.Write([]byte("GoodGoodStudy.Config.v1|" + algorithm + "|"))
	mac.Write(iv)
	mac.Write(ciphertext)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return Config{}, invalid
	}
	block, e := aes.NewCipher(key[:32])
	if e != nil {
		return Config{}, invalid
	}
	plain := make([]byte, len(ciphertext))
	defer clear(plain)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > 16 || pad > len(plain) {
		return Config{}, invalid
	}
	good := 1
	for _, v := range plain[len(plain)-pad:] {
		good &= subtle.ConstantTimeByteEq(v, byte(pad))
	}
	if good != 1 {
		return Config{}, invalid
	}
	return decodeConfig(plain[:len(plain)-pad])
}
func fetchConfig(address string, p Profile) (Config, error) {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return Config{}, invalid
	}
	if e = validateProfile(p); e != nil {
		return Config{}, e
	}
	session, e := newSession(p.DeviceID)
	if e != nil {
		return Config{}, e
	}
	body, _ := json.Marshal(session.request)
	req, e := http.NewRequest("POST", u.String(), bytes.NewReader(body))
	if e != nil {
		return Config{}, invalid
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}
	response, e := client.Do(req)
	if e != nil {
		return Config{}, errors.New("HTTPS configuration unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return Config{}, fmt.Errorf("configuration HTTP status %d", response.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, 131073))
	if e != nil || len(data) > 131072 {
		return Config{}, invalid
	}
	var r Response
	if json.Unmarshal(data, &r) != nil {
		return Config{}, invalid
	}
	return session.decrypt(r)
}
func parseINI(data string) (Config, error) {
	v := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return Config{}, invalid
		}
		v[strings.TrimSpace(parts[0])] = strings.Trim(strings.TrimSpace(parts[1]), "'\"")
	}
	minutes, e := strconv.Atoi(v["timeInterval"])
	if e != nil || minutes < 1 || minutes > 1440 {
		return Config{}, invalid
	}
	c := Config{Interval: minutes * 60, Batch: 10, Retention: 7, Storage: 512, Mail: MailConfig{true, v["smtpServer"], 587, true, v["senderMail"], v["toMail"], v["senderMail"], v["tokenCode"]}}
	b, _ := json.Marshal(c)
	defer clear(b)
	return decodeConfig(b)
}
