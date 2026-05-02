// Copyright 2026 The Match-Made/zip Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var syntheticMultipartEntries = map[string]struct {
	size   int64
	sha256 string
}{
	"file1.txt": {53337, "39da64f02b24c19780f8a8534df75366742e8ce15cdbd40872cda0d97d097805"},
	"file2.txt": {53337, "4b7563059d203d14c213750f83b8bd009d49f9433c377b31fa3b0386a5126612"},
	"file3.txt": {53337, "073ac8342d873ccad066d05bf9d53ecba625b8e1abf658a7434e8c28952a4087"},
}

func checkSyntheticMultipart(t *testing.T, rc *ReadCloser, password string, wantEncrypted bool) {
	t.Helper()
	if got := len(rc.File); got != len(syntheticMultipartEntries) {
		t.Fatalf("entry count: got %d, want %d", got, len(syntheticMultipartEntries))
	}
	for _, f := range rc.File {
		want, ok := syntheticMultipartEntries[f.Name]
		if !ok {
			t.Errorf("unexpected entry %q", f.Name)
			continue
		}
		if int64(f.UncompressedSize64) != want.size {
			t.Errorf("%s uncompressed size: got %d, want %d", f.Name, f.UncompressedSize64, want.size)
		}
		if f.IsEncrypted() != wantEncrypted {
			t.Errorf("%s IsEncrypted: got %v, want %v", f.Name, f.IsEncrypted(), wantEncrypted)
		}
		if wantEncrypted {
			f.SetPassword(password)
		}
		r, err := f.Open()
		if err != nil {
			t.Errorf("%s Open: %v", f.Name, err)
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, r)
		if cerr := r.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			t.Errorf("%s decrypt+read: %v", f.Name, err)
			continue
		}
		if n != want.size {
			t.Errorf("%s decrypted size: got %d, want %d", f.Name, n, want.size)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != want.sha256 {
			t.Errorf("%s decrypted SHA-256: got %s, want %s", f.Name, got, want.sha256)
		}
	}
}

func openSyntheticMultipart(t *testing.T, fixture string) *ReadCloser {
	t.Helper()
	rc, err := OpenReaderMultipart(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatalf("OpenReaderMultipart(%q): %v", fixture, err)
	}
	return rc
}

func TestMultipartZ01_NoEncryption(t *testing.T) {
	rc := openSyntheticMultipart(t, "multipart.zip")
	defer rc.Close()
	checkSyntheticMultipart(t, rc, "", false)
}

func TestMultipartZ01_StandardEncryption(t *testing.T) {
	rc := openSyntheticMultipart(t, "multipart-standard.zip")
	defer rc.Close()
	checkSyntheticMultipart(t, rc, "golang", true)
}

func TestMultipartVolume_NoEncryption(t *testing.T) {
	rc := openSyntheticMultipart(t, "multipart-volume.zip.001")
	defer rc.Close()
	checkSyntheticMultipart(t, rc, "", false)
}

func TestMultipartVolume_ZipCrypto(t *testing.T) {
	rc := openSyntheticMultipart(t, "multipart-volume-zipcrypto.zip.001")
	defer rc.Close()
	checkSyntheticMultipart(t, rc, "golang", true)
}

func TestMultipartVolume_AES128(t *testing.T) {
	rc := openSyntheticMultipart(t, "multipart-volume-aes128.zip.001")
	defer rc.Close()
	checkSyntheticMultipart(t, rc, "golang", true)
}

func TestMultipartVolume_AES192(t *testing.T) {
	rc := openSyntheticMultipart(t, "multipart-volume-aes192.zip.001")
	defer rc.Close()
	checkSyntheticMultipart(t, rc, "golang", true)
}

func TestMultipartVolume_AES256(t *testing.T) {
	rc := openSyntheticMultipart(t, "multipart-volume-aes256.zip.001")
	defer rc.Close()
	checkSyntheticMultipart(t, rc, "golang", true)
}

func TestMultipartRealAES(t *testing.T) {
	const (
		baseName       = "multipart-real-aes"
		expectedName   = "009209_G_000003_20260422.xls"
		expectedSize   = int64(15242240)
		expectedSHA256 = "e355208d499cbfa68ca09dc0dd2cc509b3d78e0284ddd6c1d152b37c850cbe24"
	)
	base := filepath.Join("testdata", "private", baseName)
	zipPath := base + ".zip"
	pwPath := base + ".password"

	if _, err := os.Stat(zipPath); errors.Is(err, fs.ErrNotExist) {
		t.Skipf("private multipart fixture not present: %s", zipPath)
	}
	pwBytes, err := os.ReadFile(pwPath)
	if err != nil {
		t.Fatalf("read password sidecar: %v", err)
	}
	password := strings.TrimSpace(string(pwBytes))

	rc, err := OpenReaderMultipart(zipPath)
	if err != nil {
		t.Fatalf("OpenReaderMultipart: %v", err)
	}
	defer rc.Close()

	if got := len(rc.File); got != 1 {
		t.Fatalf("entry count: got %d, want 1", got)
	}
	f := rc.File[0]
	if f.Name != expectedName {
		t.Errorf("entry name: got %q, want %q", f.Name, expectedName)
	}
	if !f.IsEncrypted() {
		t.Fatalf("expected entry to be encrypted")
	}
	f.SetPassword(password)

	r, err := f.Open()
	if err != nil {
		t.Fatalf("File.Open: %v", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, r)
	if cerr := r.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("decrypt+read: %v", err)
	}
	if n != expectedSize {
		t.Errorf("decrypted size: got %d, want %d", n, expectedSize)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expectedSHA256 {
		t.Errorf("decrypted SHA-256: got %s, want %s", got, expectedSHA256)
	}
}
