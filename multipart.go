// Copyright 2026 The Match-Made/zip Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

var (
	ErrNoParts         = errors.New("zip: no multipart sibling files found")
	ErrNotSplitArchive = errors.New("zip: first part missing PKZIP spanning marker")
)

type diskInfo struct {
	size       int64
	cumulative int64
}

type multiDiskReaderAt struct {
	parts []io.ReaderAt
	disks []diskInfo
	total int64
}

func (m *multiDiskReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("zip: negative offset")
	}
	if off >= m.total {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		idx := sort.Search(len(m.disks), func(i int) bool {
			return m.disks[i].cumulative+m.disks[i].size > off
		})
		if idx >= len(m.disks) {
			return n, io.EOF
		}
		d := m.disks[idx]
		localOff := off - d.cumulative
		want := int(d.size - localOff)
		if remaining := len(p) - n; remaining < want {
			want = remaining
		}
		nn, err := m.parts[idx].ReadAt(p[n:n+want], localOff)
		n += nn
		off += int64(nn)
		// We sized the read to stay within this part, so a short read
		// means the part itself is truncated — fail loudly rather than
		// silently rolling onto the next part.
		if nn < want {
			if err == nil || err == io.EOF {
				return n, io.ErrUnexpectedEOF
			}
			return n, err
		}
	}
	return n, nil
}

// OpenReaderMultipart opens a multipart zip archive, auto-detecting
// PKZIP true-split (.z01/.z02/.../.zip) or 7-Zip volume (.zip.001/...)
// layout. Pass the path to the .zip part or to the .001 volume.
func OpenReaderMultipart(path string) (*ReadCloser, error) {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".001") {
		return openVolumeSplit(path)
	}
	if !strings.HasSuffix(lower, ".zip") {
		return nil, fmt.Errorf("zip: multipart entry path %q must end in .zip or .001", path)
	}
	if _, err := os.Stat(path + ".001"); err == nil {
		return openVolumeSplit(path + ".001")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return openPKZIPSplit(path)
}

func openPKZIPSplit(zipPath string) (*ReadCloser, error) {
	base := zipPath[:len(zipPath)-len(".zip")]
	var paths []string
	for i := 1; ; i++ {
		p := fmt.Sprintf("%s.z%02d", base, i)
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				break
			}
			return nil, err
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		return nil, ErrNoParts
	}
	paths = append(paths, zipPath)

	files, err := openAll(paths)
	if err != nil {
		return nil, err
	}
	// Per APPNOTE 8.5.4, disk 1 of a true split archive begins with the
	// spanning marker. Catches misnamed single zips and partial sets early.
	if err := verifySpanningMarker(files[0]); err != nil {
		closeAll(files)
		return nil, err
	}
	rc, rd, err := assemble(files)
	if err != nil {
		closeAll(files)
		return nil, err
	}
	rc.disks = rd.disks
	if err := rc.init(rd, rd.total); err != nil {
		rc.Close()
		return nil, err
	}
	return rc, nil
}

func openVolumeSplit(firstVolumePath string) (*ReadCloser, error) {
	if !strings.HasSuffix(strings.ToLower(firstVolumePath), ".001") {
		return nil, fmt.Errorf("zip: volume entry path %q must end in .001", firstVolumePath)
	}
	base := firstVolumePath[:len(firstVolumePath)-len(".001")]
	var paths []string
	for i := 1; ; i++ {
		p := fmt.Sprintf("%s.%03d", base, i)
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				break
			}
			return nil, err
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		return nil, ErrNoParts
	}

	files, err := openAll(paths)
	if err != nil {
		return nil, err
	}
	rc, rd, err := assemble(files)
	if err != nil {
		closeAll(files)
		return nil, err
	}
	if err := rc.init(rd, rd.total); err != nil {
		rc.Close()
		return nil, err
	}
	return rc, nil
}

func openAll(paths []string) ([]*os.File, error) {
	files := make([]*os.File, 0, len(paths))
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			closeAll(files)
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

func closeAll(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}

func verifySpanningMarker(f *os.File) error {
	var sig [4]byte
	if _, err := f.ReadAt(sig[:], 0); err != nil {
		if err == io.EOF {
			return ErrNotSplitArchive
		}
		return err
	}
	if binary.LittleEndian.Uint32(sig[:]) != dataDescriptorSignature {
		return ErrNotSplitArchive
	}
	return nil
}

func assemble(files []*os.File) (*ReadCloser, *multiDiskReaderAt, error) {
	disks := make([]diskInfo, len(files))
	parts := make([]io.ReaderAt, len(files))
	var total int64
	for i, f := range files {
		st, err := f.Stat()
		if err != nil {
			return nil, nil, err
		}
		size := st.Size()
		disks[i] = diskInfo{size: size, cumulative: total}
		parts[i] = f
		total += size
	}
	rc := &ReadCloser{f: files[len(files)-1]}
	for _, f := range files[:len(files)-1] {
		rc.extras = append(rc.extras, f)
	}
	return rc, &multiDiskReaderAt{parts: parts, disks: disks, total: total}, nil
}
