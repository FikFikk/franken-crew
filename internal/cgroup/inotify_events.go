package cgroup

import (
	"encoding/binary"
	"fmt"
)

// Mask event inotify sesuai ABI kernel Linux (include/uapi/linux/inotify.h). Didefinisikan ulang di sini agar
// parser murni dapat dikompilasi dan diuji di semua OS; inotify_linux_test.go mencocokkannya dengan x/sys/unix.
const (
	inModify     uint32 = 0x00000002
	inAttrib     uint32 = 0x00000004
	inDeleteSelf uint32 = 0x00000400
	inUnmount    uint32 = 0x00002000
	inQOverflow  uint32 = 0x00004000
	inIgnored    uint32 = 0x00008000

	// inotifyEventHeaderSize adalah sizeof(struct inotify_event) tanpa name: wd, mask, cookie, len (masing-masing 4 byte).
	inotifyEventHeaderSize = 16
)

// inotifyBatch merangkum seluruh record inotify_event hasil satu kali read(2).
type inotifyBatch struct {
	// modified: ada IN_MODIFY/IN_ATTRIB untuk watch ini, atau IN_Q_OVERFLOW (event terbuang), sehingga berkas
	// harus dibaca ulang.
	modified bool
	// gone: ada IN_IGNORED/IN_DELETE_SELF/IN_UNMOUNT untuk watch ini, sehingga watch tidak lagi menerima event.
	gone bool
}

// parseInotifyEvents mem-parsing setiap record inotify_event berukuran variabel di buf (header 16 byte dalam
// urutan byte native lalu name sepanjang len) dan merangkum event milik watch descriptor wd. Buffer yang
// berakhir di tengah record dianggap rusak karena kernel selalu mengembalikan record utuh.
func parseInotifyEvents(buf []byte, wd int32) (inotifyBatch, error) {
	var batch inotifyBatch
	for off := 0; off < len(buf); {
		remaining := len(buf) - off
		if remaining < inotifyEventHeaderSize {
			return inotifyBatch{}, fmt.Errorf("truncated inotify event at offset %d: %d bytes left, header needs %d",
				off, remaining, inotifyEventHeaderSize)
		}
		eventWd := int32(binary.NativeEndian.Uint32(buf[off:]))
		mask := binary.NativeEndian.Uint32(buf[off+4:])
		nameLen := binary.NativeEndian.Uint32(buf[off+12:])
		// Bandingkan sebagai uint64 agar len raksasa tidak overflow menjadi negatif pada platform 32-bit.
		if uint64(nameLen) > uint64(remaining-inotifyEventHeaderSize) {
			return inotifyBatch{}, fmt.Errorf("inotify event at offset %d declares a %d-byte name but only %d bytes follow",
				off, nameLen, remaining-inotifyEventHeaderSize)
		}
		off += inotifyEventHeaderSize + int(nameLen)

		// Antrean kernel penuh (wd = -1): event mungkin terbuang, jadi berkas tetap harus dibaca ulang.
		if mask&inQOverflow != 0 {
			batch.modified = true
		}
		if eventWd != wd {
			continue
		}
		if mask&(inModify|inAttrib) != 0 {
			batch.modified = true
		}
		if mask&(inIgnored|inDeleteSelf|inUnmount) != 0 {
			batch.gone = true
		}
	}
	return batch, nil
}
