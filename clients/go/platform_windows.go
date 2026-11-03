//go:build windows

package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"image"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

func stateDir() (string, error) {
	p := os.Getenv("LOCALAPPDATA")
	if p == "" {
		return "", errors.New("LOCALAPPDATA missing")
	}
	return filepath.Join(p, "GoodGoodStudy"), nil
}
func currentSID() (string, error) {
	t := windows.GetCurrentProcessToken()
	u, e := t.GetTokenUser()
	if e != nil {
		return "", e
	}
	return u.User.Sid.String(), nil
}

var crypt32 = windows.NewLazySystemDLL("crypt32.dll")
var protect = crypt32.NewProc("CryptProtectData")
var unprotect = crypt32.NewProc("CryptUnprotectData")

type blob struct {
	N    uint32
	Data *byte
}

func makeBlob(b []byte) blob {
	if len(b) == 0 {
		return blob{}
	}
	return blob{uint32(len(b)), &b[0]}
}
func dpapi(data []byte, decrypt bool) ([]byte, error) {
	in := makeBlob(data)
	entropyBytes := []byte("GoodGoodStudy.DeviceCredential.v2")
	entropy := makeBlob(entropyBytes)
	var out blob
	var result uintptr
	if decrypt {
		result, _, _ = unprotect.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&entropy)), 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	} else {
		result, _, _ = protect.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&entropy)), 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	}
	if result == 0 {
		return nil, errors.New("DPAPI failed")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	memory := unsafe.Slice(out.Data, int(out.N))
	resultBytes := append([]byte{}, memory...)
	clear(memory)
	return resultBytes, nil
}
func privateWrite(path string, data []byte) error {
	path, e := filepath.Abs(path)
	if e != nil || strings.HasPrefix(path, `\\`) {
		return invalid
	}
	sid, e := currentSID()
	if e != nil {
		return e
	}
	descriptor, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid + ")")
	if e != nil {
		return e
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return invalid
	}
	h, e := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return errors.New("private output exists or cannot be created")
	}
	file := os.NewFile(uintptr(h), path)
	defer file.Close()
	_, e = file.Write(data)
	if e == nil {
		e = file.Sync()
	}
	return e
}

type guard struct{ mutex, stop windows.Handle }

func acquireGuard() (*guard, error) {
	sid, e := currentSID()
	if e != nil {
		return nil, e
	}
	name, _ := windows.UTF16PtrFromString("Local\\GoodGoodStudy-" + sid)
	m, e := windows.CreateMutex(nil, true, name)
	if e == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(m)
		return nil, errors.New("already running")
	}
	if e != nil {
		return nil, e
	}
	evname, _ := windows.UTF16PtrFromString("Local\\GoodGoodStudyStop-" + sid)
	ev, e := windows.CreateEvent(nil, 1, 0, evname)
	if e != nil {
		windows.ReleaseMutex(m)
		windows.CloseHandle(m)
		return nil, e
	}
	return &guard{m, ev}, nil
}
func (g *guard) close() {
	windows.CloseHandle(g.stop)
	windows.ReleaseMutex(g.mutex)
	windows.CloseHandle(g.mutex)
}
func (g *guard) wait(ms uint32) bool {
	r, e := windows.WaitForSingleObject(g.stop, ms)
	return e != nil || r == windows.WAIT_OBJECT_0
}
func (g *guard) signal() { windows.SetEvent(g.stop) }

var user32 = windows.NewLazySystemDLL("user32.dll")
var gdi32 = windows.NewLazySystemDLL("gdi32.dll")
var getDC = user32.NewProc("GetDC")
var releaseDC = user32.NewProc("ReleaseDC")
var metric = user32.NewProc("GetSystemMetrics")
var compatible = gdi32.NewProc("CreateCompatibleDC")
var deleteDC = gdi32.NewProc("DeleteDC")
var dib = gdi32.NewProc("CreateDIBSection")
var selectObject = gdi32.NewProc("SelectObject")
var deleteObject = gdi32.NewProc("DeleteObject")
var bitblt = gdi32.NewProc("BitBlt")
var gdiFlush = gdi32.NewProc("GdiFlush")

type bitmapHeader struct {
	Size                   uint32
	Width, Height          int32
	Planes, Bits           uint16
	Compression, ImageSize uint32
	X, Y                   int32
	Used, Important        uint32
}
type bitmapInfo struct {
	Header bitmapHeader
	Colors [1]uint32
}

func captureImage() (*image.RGBA, error) {
	user32.NewProc("SetProcessDPIAware").Call()
	w, _, _ := metric.Call(0)
	h, _, _ := metric.Call(1)
	if w == 0 || h == 0 || w > 16384 || h > 16384 || uint64(w)*uint64(h) > 64000000 {
		return nil, errors.New("invalid screen bounds")
	}
	source, _, _ := getDC.Call(0)
	if source == 0 {
		return nil, errors.New("screen DC unavailable")
	}
	defer releaseDC.Call(0, source)
	dc, _, _ := compatible.Call(source)
	if dc == 0 {
		return nil, errors.New("capture DC unavailable")
	}
	defer deleteDC.Call(dc)
	info := bitmapInfo{Header: bitmapHeader{Size: 40, Width: int32(w), Height: -int32(h), Planes: 1, Bits: 32}}
	var pixels unsafe.Pointer
	bitmap, _, _ := dib.Call(source, uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&pixels)), 0, 0)
	if bitmap == 0 || pixels == nil {
		return nil, errors.New("bitmap unavailable")
	}
	defer deleteObject.Call(bitmap)
	old, _, _ := selectObject.Call(dc, bitmap)
	if old == 0 || old == ^uintptr(0) {
		return nil, errors.New("bitmap selection failed")
	}
	defer selectObject.Call(dc, old)
	ok, _, _ := bitblt.Call(dc, 0, 0, w, h, source, 0, 0, 0x00CC0020|0x40000000)
	if ok == 0 {
		return nil, errors.New("screen copy failed")
	}
	// DIB memory can only be read after the drawing batch has completed.
	ok, _, _ = gdiFlush.Call()
	if ok == 0 {
		return nil, errors.New("screen synchronization failed")
	}
	bytes := unsafe.Slice((*byte)(pixels), int(w*h*4))
	result := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	for i := 0; i < len(bytes); i += 4 {
		result.Pix[i] = bytes[i+2]
		result.Pix[i+1] = bytes[i+1]
		result.Pix[i+2] = bytes[i]
		result.Pix[i+3] = 255
	}
	return result, nil
}
func atomicWrite(path string, data []byte) error {
	temp := path + ".tmp"
	if e := os.WriteFile(temp, data, 0600); e != nil {
		return e
	}
	defer os.Remove(temp)
	from, e := windows.UTF16PtrFromString(temp)
	if e != nil {
		return e
	}
	to, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
