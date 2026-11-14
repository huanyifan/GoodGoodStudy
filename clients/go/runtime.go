package main

import (
	"archive/zip"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var logGate sync.Mutex

func logLine(root, message string) {
	logGate.Lock()
	defer logGate.Unlock()
	path := filepath.Join(root, "runtime.log")
	if f, e := os.Stat(path); e == nil && f.Size() > 1048576 {
		os.Remove(path + ".1")
		os.Rename(path, path+".1")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, time.Now().UTC().Format(time.RFC3339)+" "+message)
}
func unique(ext string) string {
	b, _ := random(16)
	return "ggs-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + fmt.Sprintf("%x", b) + ext
}
func images(directory, extension string) ([]string, error) {
	entries, e := os.ReadDir(directory)
	if e != nil {
		return nil, e
	}
	var result []string
	for _, f := range entries {
		if !f.IsDir() && strings.HasPrefix(f.Name(), "ggs-") && strings.HasSuffix(f.Name(), extension) {
			result = append(result, filepath.Join(directory, f.Name()))
		}
	}
	sort.Strings(result)
	return result, nil
}
func stored(dirs ...string) int64 {
	var total int64
	for _, dir := range dirs {
		list, _ := os.ReadDir(dir)
		for _, entry := range list {
			if !entry.IsDir() {
				if f, e := entry.Info(); e == nil {
					total += f.Size()
				}
			}
		}
	}
	return total
}

// maxAttachmentBytes is the largest archive the sender will attach.
const maxAttachmentBytes = 10 * 1024 * 1024

// maxBatchSourceBytes leaves headroom for ZIP overhead; PNGs barely compress.
const maxBatchSourceBytes = 9 * 1024 * 1024

// oversizeSuffix marks archives that can never be mailed; kept until pruned.
const oversizeSuffix = ".oversize"

// prune applies retention and the storage limit to captures and the mail
// queue. Expired files go first; if still at or above limit, the oldest
// managed files (time-ordered ggs- names) are removed until it fits, so unsent
// batches are dropped oldest-first instead of pausing capture indefinitely.
func prune(directory string, days int, limit int64, queue string) {
	type managed struct {
		name, path string
		size       int64
	}
	var list []managed
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	for _, dir := range []string{directory, queue} {
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasPrefix(name, "ggs-") || strings.HasSuffix(name, ".tmp") {
				continue
			}
			info, e := entry.Info()
			if e != nil {
				continue
			}
			path := filepath.Join(dir, name)
			if info.ModTime().Before(cutoff) {
				os.Remove(path)
				continue
			}
			list = append(list, managed{name, path, info.Size()})
		}
	}
	total := stored(directory, queue)
	if total < limit {
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
	for _, m := range list {
		if total < limit {
			break
		}
		if os.Remove(m.path) == nil {
			total -= m.size
		}
	}
}

// nextBatch reports how many leading files form the next batch (0 = wait).
// A batch closes at batchSize files or before the next file would push the
// source total past maxBytes; one oversized file forms its own batch.
func nextBatch(sizes []int64, batchSize int, maxBytes int64) int {
	var total int64
	for i, size := range sizes {
		if i > 0 && total+size > maxBytes {
			return i
		}
		total += size
		if i+1 >= batchSize || total >= maxBytes {
			return i + 1
		}
	}
	return 0
}

// archiveReady archives every complete batch currently waiting.
func archiveReady(directory, queue string, batchSize int, root string) {
	for {
		list, e := images(directory, ".png")
		if e != nil {
			return
		}
		sizes := make([]int64, len(list))
		for i, p := range list {
			if f, err := os.Stat(p); err == nil {
				sizes[i] = f.Size()
			}
		}
		n := nextBatch(sizes, batchSize, maxBatchSourceBytes)
		if n == 0 {
			return
		}
		if _, e = archiveBatch(queue, list[:n]); e != nil {
			logLine(root, "Archive failed: "+e.Error()+"; recoverable files retained.")
			return
		}
	}
}

// quarantine moves an unsendable archive out of the mail queue.
func quarantine(path string) (string, error) {
	target := path + oversizeSuffix
	return target, os.Rename(path, target)
}
func capture(directory string) error {
	img, e := captureImage()
	if e != nil {
		return e
	}
	final := filepath.Join(directory, unique(".png"))
	temp := final + ".tmp"
	out, e := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer os.Remove(temp)
	e = png.Encode(out, img)
	if e == nil {
		e = out.Sync()
	}
	closeErr := out.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(temp, final)
}
func archiveBatch(queue string, files []string) (string, error) {
	if len(files) == 0 {
		return "", invalid
	}
	for _, p := range files {
		if _, e := os.Stat(p); e != nil {
			return "", e
		}
	}
	final := filepath.Join(queue, unique(".zip"))
	temp := final + ".tmp"
	out, e := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	defer os.Remove(temp)
	z := zip.NewWriter(out)
	for _, p := range files {
		header := &zip.FileHeader{Name: filepath.Base(p), Method: zip.Deflate}
		entry, err := z.CreateHeader(header)
		if err != nil {
			e = err
			break
		}
		source, err := os.Open(p)
		if err != nil {
			e = err
			break
		}
		_, err = io.Copy(entry, source)
		source.Close()
		if err != nil {
			e = err
			break
		}
	}
	if err := z.Close(); e == nil {
		e = err
	}
	if e == nil {
		e = out.Sync()
	}
	if err := out.Close(); e == nil {
		e = err
	}
	if e != nil {
		return "", e
	}
	if e = os.Rename(temp, final); e != nil {
		return "", e
	}
	for _, p := range files {
		if e = os.Remove(p); e != nil {
			return final, e
		}
	}
	return final, nil
}

// smtpIdleTimeout bounds each network read/write rather than the whole
// session, so a 10 MiB attachment on a slow uplink is not cut off at 15 s.
const smtpIdleTimeout = 30 * time.Second

// idleConn refreshes the deadline before every read and write.
type idleConn struct{ net.Conn }

func (c idleConn) Read(b []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(smtpIdleTimeout))
	return c.Conn.Read(b)
}
func (c idleConn) Write(b []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(smtpIdleTimeout))
	return c.Conn.Write(b)
}

// implicitTLS reports whether the port expects TLS from the first byte
// (SMTPS 465, IMAP-style 994 used by some providers) instead of STARTTLS.
func implicitTLS(port int) bool { return port == 465 || port == 994 }

func sendArchive(c MailConfig, path string) error {
	tlsConfig := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	address := net.JoinHostPort(c.Host, fmt.Sprint(c.Port))
	raw, e := net.DialTimeout("tcp", address, 15*time.Second)
	if e != nil {
		return e
	}
	var connection net.Conn = idleConn{raw}
	if implicitTLS(c.Port) {
		secure := tls.Client(connection, tlsConfig)
		if e = secure.Handshake(); e != nil {
			raw.Close()
			return e
		}
		connection = secure
	}
	defer connection.Close()
	client, e := smtp.NewClient(connection, c.Host)
	if e != nil {
		return e
	}
	defer client.Close()
	if !implicitTLS(c.Port) {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP STARTTLS required")
		}
		if e = client.StartTLS(tlsConfig); e != nil {
			return e
		}
	}
	if e = client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); e != nil {
		return e
	}
	if e = client.Mail(c.Sender); e != nil {
		return e
	}
	if e = client.Rcpt(c.Recipient); e != nil {
		return e
	}
	data, e := client.Data()
	if e != nil {
		return e
	}
	writer := multipart.NewWriter(data)
	host, _ := os.Hostname()
	fmt.Fprintf(data, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n", c.Sender, c.Recipient, mime.QEncoding.Encode("utf-8", host+" screenshots"), writer.Boundary())
	part, e := writer.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}})
	if e != nil {
		return e
	}
	io.WriteString(part, "GoodGoodStudy screenshot batch.\r\n")
	part, e = writer.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/zip"}, "Content-Disposition": {fmt.Sprintf("attachment; filename=%q", filepath.Base(path))}, "Content-Transfer-Encoding": {"base64"}})
	if e != nil {
		return e
	}
	content, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	encoded := base64.StdEncoding.EncodeToString(content)
	for len(encoded) > 0 {
		n := 76
		if len(encoded) < n {
			n = len(encoded)
		}
		if _, e = io.WriteString(part, encoded[:n]+"\r\n"); e != nil {
			return e
		}
		encoded = encoded[n:]
	}
	if e = writer.Close(); e != nil {
		return e
	}
	if e = data.Close(); e != nil {
		return e
	}
	return client.Quit()
}
func sender(c Config, queue, root string, g *guard, wg *sync.WaitGroup) {
	defer wg.Done()
	retry := 5
	for !g.wait(0) {
		failed := false
		list, _ := images(queue, ".zip")
		for _, path := range list {
			if g.wait(0) {
				return
			}
			f, e := os.Stat(path)
			if e != nil {
				continue
			}
			if f.Size() > maxAttachmentBytes {
				if _, e := quarantine(path); e != nil {
					logLine(root, "Oversize archive could not be moved aside: "+e.Error())
					failed = true
					break
				}
				logLine(root, "Oversize archive moved aside (*.zip.oversize); 10 MiB mail limit.")
				continue
			}
			if e := sendArchive(c.Mail, path); e != nil {
				logLine(root, "Mail failed: "+e.Error()+"; archive retained.")
				failed = true
				break
			}
			if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
				logLine(root, "Sent archive could not be removed; delivery may repeat.")
				failed = true
				break
			}
			logLine(root, "Screenshot batch sent.")
		}
		if failed {
			retry *= 2
			if retry > 300 {
				retry = 300
			}
		} else {
			retry = 5
		}
		if g.wait(uint32(retry * 1000)) {
			return
		}
	}
}
func runApp(address, root string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	g, e := acquireGuard()
	if e != nil {
		return e
	}
	defer g.close()
	profile, e := loadProfile(root)
	if e != nil {
		return e
	}
	c, e := fetchConfig(address, profile)
	profile.Key = ""
	if e != nil {
		return e
	}
	directory := c.Directory
	if directory == "" {
		directory = filepath.Join(root, "captures")
	}
	queue := filepath.Join(root, "pending")
	for _, path := range []string{directory, queue} {
		if e = os.MkdirAll(path, 0700); e != nil {
			return e
		}
	}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	go func() { <-interrupts; g.signal() }()
	var wg sync.WaitGroup
	if c.Mail.Enabled {
		wg.Add(1)
		go sender(c, queue, root, g, &wg)
	}
	defer func() { g.signal(); wg.Wait() }()
	fmt.Println("GoodGoodStudy Go running. Ctrl+C to stop.")
	logLine(root, "Go capture started.")
	interval := time.Duration(c.Interval) * time.Second
	next := time.Now().Add(interval)
	for {
		wait := time.Until(next)
		if wait < 0 {
			wait = 0
		}
		if g.wait(uint32(wait / time.Millisecond)) {
			return nil
		}
		limit := int64(c.Storage) * 1024 * 1024
		prune(directory, c.Retention, limit, queue)
		if stored(directory, queue) < limit {
			if e := capture(directory); e != nil {
				logLine(root, "Capture failed: "+e.Error()+"; retry at next interval.")
			}
		} else {
			logLine(root, "Storage limit reached; capture skipped.")
		}
		if c.Mail.Enabled {
			archiveReady(directory, queue, c.Batch, root)
		}
		next = next.Add(interval)
		if next.Before(time.Now()) {
			next = time.Now().Add(interval)
		}
	}
}
