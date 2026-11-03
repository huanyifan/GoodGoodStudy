package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func saveProfile(root string, p Profile) error {
	if e := validateProfile(p); e != nil {
		return e
	}
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	defer clear(b)
	encrypted, e := dpapi(b, false)
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(root, "device-profile.dpapi"), encrypted)
}
func loadProfile(root string) (Profile, error) {
	var p Profile
	b, e := os.ReadFile(filepath.Join(root, "device-profile.dpapi"))
	if e != nil {
		return p, errors.New("import device profile first")
	}
	plain, e := dpapi(b, true)
	if e != nil {
		return p, e
	}
	defer clear(plain)
	if json.Unmarshal(plain, &p) != nil {
		return p, invalid
	}
	return p, validateProfile(p)
}
func run(args []string) error {
	root, e := stateDir()
	if e != nil {
		return e
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return e
	}
	exists := func() bool { _, e := os.Stat(filepath.Join(root, "device-profile.dpapi")); return e == nil }
	if len(args) > 0 {
		switch args[0] {
		case "--create-profile":
			if len(args) != 2 || exists() {
				return invalid
			}
			p, e := newProfile()
			if e != nil {
				return e
			}
			b, _ := json.Marshal(p)
			defer clear(b)
			if e = privateWrite(args[1], b); e != nil {
				return e
			}
			if e = saveProfile(root, p); e != nil {
				return e
			}
			fmt.Println("Device credential created; enroll its hash on the server.")
			return nil
		case "--import-profile":
			if (len(args) != 2 && !(len(args) == 3 && args[2] == "--replace")) || (exists() && len(args) != 3) {
				return invalid
			}
			f, e := os.Stat(args[1])
			if e != nil || f.Size() > 4096 {
				return invalid
			}
			b, e := os.ReadFile(args[1])
			if e != nil {
				return invalid
			}
			defer clear(b)
			var p Profile
			if json.Unmarshal(b, &p) != nil {
				return invalid
			}
			if e = saveProfile(root, p); e != nil {
				return e
			}
			fmt.Println("Device credential imported with DPAPI; no session encryption key stored.")
			return nil
		case "--export-profile":
			if len(args) != 2 {
				return invalid
			}
			p, e := loadProfile(root)
			if e != nil {
				return e
			}
			b, _ := json.Marshal(p)
			defer clear(b)
			return privateWrite(args[1], b)
		case "--convert-ini":
			if len(args) != 3 {
				return invalid
			}
			f, e := os.Stat(args[1])
			if e != nil || f.Size() > 65536 {
				return invalid
			}
			b, e := os.ReadFile(args[1])
			if e != nil {
				return invalid
			}
			defer clear(b)
			c, e := parseINI(string(b))
			if e != nil {
				return e
			}
			output, _ := json.Marshal(c)
			defer clear(output)
			if e = privateWrite(args[2], output); e != nil {
				return e
			}
			fmt.Println("Private server configuration written; keep outside public web root.")
			return nil
		case "--check-config":
			if len(args) > 2 {
				return invalid
			}
			address := endpoint
			if len(args) == 2 {
				address = args[1]
			}
			p, e := loadProfile(root)
			if e != nil {
				return e
			}
			if _, e = fetchConfig(address, p); e != nil {
				return e
			}
			fmt.Println("Go HTTPS/ECDH configuration validated; no screenshots or email.")
			return nil
		}
	}
	address := endpoint
	if len(args) > 0 {
		if len(args) != 2 || args[0] != "--config-url" {
			return invalid
		}
		address = args[1]
	}
	return runApp(address, root)
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "GoodGoodStudy stopped; check profile, HTTPS configuration and logs.")
		os.Exit(1)
	}
}
