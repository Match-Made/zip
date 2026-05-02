// Copyright 2026 The Match-Made/zip Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"
)

// TestZip64AsymmetricPromotion verifies that the central-directory zip64
// extra-block parser honors APPNOTE 4.5.3: only the fields whose 32-bit
// counterpart was sentinel-promoted (0xFFFFFFFF) appear in the extra
// block, in field order.
//
// The fixture is a hand-rolled archive with one stored entry "asym"
// containing "hi", where the 32-bit local-header offset is set to the
// sentinel and the zip64 extra contains *only* the 8-byte real offset.
// Sizes stay in 32-bit form. Before the sentinel-aware fix, the parser
// would consume the offset bytes as UncompressedSize64 and leave
// headerOffset stuck at 0xFFFFFFFF.
func TestZip64AsymmetricPromotion(t *testing.T) {
	const (
		filename = "asym"
		content  = "hi"
	)

	var buf bytes.Buffer

	// Local file header at offset 0.
	localHeaderOffset := uint64(buf.Len())
	writeLocalFileHeader(&buf, filename, content)
	buf.WriteString(content)

	// Central directory header. headerOffset field is sentinel; real
	// offset goes in the zip64 extra. Sizes are NOT sentinel.
	cdOffset := uint64(buf.Len())
	writeCentralDirHeaderAsymmetric(&buf, filename, content, localHeaderOffset)
	cdSize := uint64(buf.Len()) - cdOffset

	// EOCD. No zip64 EOCD needed — only the offset field was promoted,
	// and the EOCD itself records cdOffset which fits in 32 bits.
	writeEOCD(&buf, cdOffset, cdSize, 1)

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if got := len(zr.File); got != 1 {
		t.Fatalf("entry count: got %d, want 1", got)
	}
	f := zr.File[0]
	if f.Name != filename {
		t.Errorf("Name: got %q, want %q", f.Name, filename)
	}
	// The bug under test would leave headerOffset at uint32max.
	if f.headerOffset != int64(localHeaderOffset) {
		t.Errorf("headerOffset: got %d, want %d (still sentinel? %v)",
			f.headerOffset, localHeaderOffset, f.headerOffset == int64(uint32max))
	}
	if f.UncompressedSize64 != uint64(len(content)) {
		t.Errorf("UncompressedSize64: got %d, want %d", f.UncompressedSize64, len(content))
	}

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(rc)
	if cerr := rc.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != content {
		t.Errorf("contents: got %q, want %q", got, content)
	}
}

// TestZip64AsymmetricPromotion_TruncatedExtra verifies that a malformed
// archive — one that claims sentinel promotion but provides too few
// bytes in the zip64 extra — is rejected with ErrFormat instead of
// silently corrupting the parsed offsets.
func TestZip64AsymmetricPromotion_TruncatedExtra(t *testing.T) {
	const (
		filename = "trunc"
		content  = "hi"
	)

	var buf bytes.Buffer
	localHeaderOffset := uint64(buf.Len())
	writeLocalFileHeader(&buf, filename, content)
	buf.WriteString(content)

	// Central directory entry with sentinel offset but a zip64 extra
	// of size 0 — i.e. it claims promotion but supplies no offset.
	cdOffset := uint64(buf.Len())
	writeCentralDirHeaderTruncatedExtra(&buf, filename, content, localHeaderOffset)
	cdSize := uint64(buf.Len()) - cdOffset
	writeEOCD(&buf, cdOffset, cdSize, 1)

	_, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != ErrFormat {
		t.Fatalf("got %v, want ErrFormat", err)
	}
}

func writeLocalFileHeader(buf *bytes.Buffer, name, content string) {
	binary.Write(buf, binary.LittleEndian, uint32(fileHeaderSignature))
	binary.Write(buf, binary.LittleEndian, uint16(20))                                  // version needed
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // flags
	binary.Write(buf, binary.LittleEndian, uint16(Store))                               // method
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // mod time
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // mod date
	binary.Write(buf, binary.LittleEndian, crc32.ChecksumIEEE([]byte(content)))         // CRC-32
	binary.Write(buf, binary.LittleEndian, uint32(len(content)))                        // compressed size
	binary.Write(buf, binary.LittleEndian, uint32(len(content)))                        // uncompressed size
	binary.Write(buf, binary.LittleEndian, uint16(len(name)))                           // filename length
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // extra length
	buf.WriteString(name)
}

func writeCentralDirHeaderAsymmetric(buf *bytes.Buffer, name, content string, realOffset uint64) {
	const extraLen = 4 + 8 // tag+size header + 8-byte offset only

	binary.Write(buf, binary.LittleEndian, uint32(directoryHeaderSignature))
	binary.Write(buf, binary.LittleEndian, uint16(20))                                  // version made by
	binary.Write(buf, binary.LittleEndian, uint16(45))                                  // version needed (zip64)
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // flags
	binary.Write(buf, binary.LittleEndian, uint16(Store))                               // method
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // mod time
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // mod date
	binary.Write(buf, binary.LittleEndian, crc32.ChecksumIEEE([]byte(content)))         // CRC-32
	binary.Write(buf, binary.LittleEndian, uint32(len(content)))                        // compressed size (NOT sentinel)
	binary.Write(buf, binary.LittleEndian, uint32(len(content)))                        // uncompressed size (NOT sentinel)
	binary.Write(buf, binary.LittleEndian, uint16(len(name)))                           // filename length
	binary.Write(buf, binary.LittleEndian, uint16(extraLen))                            // extra length
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // comment length
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // disk number start
	binary.Write(buf, binary.LittleEndian, uint16(0))                                   // internal attrs
	binary.Write(buf, binary.LittleEndian, uint32(0))                                   // external attrs
	binary.Write(buf, binary.LittleEndian, uint32(uint32max))                           // header offset = SENTINEL
	buf.WriteString(name)

	// Zip64 extra block: only the 8-byte offset.
	binary.Write(buf, binary.LittleEndian, uint16(zip64ExtraId))
	binary.Write(buf, binary.LittleEndian, uint16(8))
	binary.Write(buf, binary.LittleEndian, realOffset)
}

func writeCentralDirHeaderTruncatedExtra(buf *bytes.Buffer, name, content string, realOffset uint64) {
	const extraLen = 4 // tag+size header only, no payload

	binary.Write(buf, binary.LittleEndian, uint32(directoryHeaderSignature))
	binary.Write(buf, binary.LittleEndian, uint16(20))
	binary.Write(buf, binary.LittleEndian, uint16(45))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(Store))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, crc32.ChecksumIEEE([]byte(content)))
	binary.Write(buf, binary.LittleEndian, uint32(len(content)))
	binary.Write(buf, binary.LittleEndian, uint32(len(content)))
	binary.Write(buf, binary.LittleEndian, uint16(len(name)))
	binary.Write(buf, binary.LittleEndian, uint16(extraLen))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(uint32max))
	buf.WriteString(name)

	binary.Write(buf, binary.LittleEndian, uint16(zip64ExtraId))
	binary.Write(buf, binary.LittleEndian, uint16(0)) // claims promotion, supplies nothing
}

func writeEOCD(buf *bytes.Buffer, cdOffset, cdSize uint64, entries uint16) {
	binary.Write(buf, binary.LittleEndian, uint32(directoryEndSignature))
	binary.Write(buf, binary.LittleEndian, uint16(0))                  // disk number
	binary.Write(buf, binary.LittleEndian, uint16(0))                  // disk with start of CD
	binary.Write(buf, binary.LittleEndian, uint16(entries))            // entries on this disk
	binary.Write(buf, binary.LittleEndian, uint16(entries))            // total entries
	binary.Write(buf, binary.LittleEndian, uint32(cdSize))             // CD size
	binary.Write(buf, binary.LittleEndian, uint32(cdOffset))           // CD offset
	binary.Write(buf, binary.LittleEndian, uint16(0))                  // comment length
}
