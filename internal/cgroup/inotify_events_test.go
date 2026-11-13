package cgroup

import (
	"encoding/binary"
	"testing"
)

// Nilai mask dari include/uapi/linux/inotify.h, ditulis ulang di test agar ekspektasi tidak bergantung pada
// konstanta produksi.
const (
	abiInModify     = 0x00000002
	abiInAttrib     = 0x00000004
	abiInOpen       = 0x00000020
	abiInDeleteSelf = 0x00000400
	abiInUnmount    = 0x00002000
	abiInQOverflow  = 0x00004000
	abiInIgnored    = 0x00008000
)

// rawInotifyEvent adalah satu struct inotify_event sintetis; name dipad NUL hingga nameLen byte seperti di kernel.
type rawInotifyEvent struct {
	wd      int32
	mask    uint32
	cookie  uint32
	nameLen uint32
	name    string
}

// encodeInotifyEvents menyusun buffer hasil read(2) inotify: header 16 byte (wd, mask, cookie, len) dalam
// urutan byte native diikuti name sepanjang len.
func encodeInotifyEvents(events ...rawInotifyEvent) []byte {
	var buf []byte
	for _, ev := range events {
		header := make([]byte, 16)
		binary.NativeEndian.PutUint32(header[0:4], uint32(ev.wd))
		binary.NativeEndian.PutUint32(header[4:8], ev.mask)
		binary.NativeEndian.PutUint32(header[8:12], ev.cookie)
		binary.NativeEndian.PutUint32(header[12:16], ev.nameLen)
		name := make([]byte, ev.nameLen)
		copy(name, ev.name)
		buf = append(buf, header...)
		buf = append(buf, name...)
	}
	return buf
}

func TestParseInotifyEvents(t *testing.T) {
	const wd = 3
	// Name record: bila panjang name diabaikan, byte "memory.events" terbaca sebagai header palsu dan
	// IN_IGNORED sesudahnya tidak pernah terlihat.
	named := rawInotifyEvent{wd: wd, mask: abiInOpen, nameLen: 32, name: "memory.events"}

	cases := []struct {
		name string
		buf  []byte
		want inotifyBatch
	}{
		{
			name: "modify then ignored in one read",
			buf: encodeInotifyEvents(
				rawInotifyEvent{wd: wd, mask: abiInModify},
				rawInotifyEvent{wd: wd, mask: abiInIgnored},
			),
			want: inotifyBatch{modified: true, gone: true},
		},
		{
			name: "record with a name between modify and ignored",
			buf: encodeInotifyEvents(
				rawInotifyEvent{wd: wd, mask: abiInModify},
				named,
				rawInotifyEvent{wd: wd, mask: abiInIgnored},
			),
			want: inotifyBatch{modified: true, gone: true},
		},
		{
			name: "name bytes are never parsed as a header",
			buf:  encodeInotifyEvents(named, rawInotifyEvent{wd: wd, mask: abiInIgnored}),
			want: inotifyBatch{gone: true},
		},
		{
			name: "attrib only",
			buf:  encodeInotifyEvents(rawInotifyEvent{wd: wd, mask: abiInAttrib}),
			want: inotifyBatch{modified: true},
		},
		{
			name: "queue overflow carries wd -1 and forces a re-read",
			buf:  encodeInotifyEvents(rawInotifyEvent{wd: -1, mask: abiInQOverflow}),
			want: inotifyBatch{modified: true},
		},
		{
			name: "delete self then ignored",
			buf: encodeInotifyEvents(
				rawInotifyEvent{wd: wd, mask: abiInAttrib},
				rawInotifyEvent{wd: wd, mask: abiInDeleteSelf},
				rawInotifyEvent{wd: wd, mask: abiInIgnored},
			),
			want: inotifyBatch{modified: true, gone: true},
		},
		{
			name: "delete self alone",
			buf:  encodeInotifyEvents(rawInotifyEvent{wd: wd, mask: abiInDeleteSelf}),
			want: inotifyBatch{gone: true},
		},
		{
			name: "unmount",
			buf:  encodeInotifyEvents(rawInotifyEvent{wd: wd, mask: abiInUnmount}),
			want: inotifyBatch{gone: true},
		},
		{
			name: "events of another watch descriptor are ignored",
			buf: encodeInotifyEvents(
				rawInotifyEvent{wd: wd + 1, mask: abiInModify},
				rawInotifyEvent{wd: wd + 1, mask: abiInIgnored},
			),
			want: inotifyBatch{},
		},
		{
			name: "empty read",
			buf:  nil,
			want: inotifyBatch{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseInotifyEvents(tc.buf, wd)
			if err != nil {
				t.Fatalf("parseInotifyEvents returned error: %v", err)
			}
			if got != tc.want {
				t.Errorf("parseInotifyEvents = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseInotifyEvents_RejectsTruncatedRecords(t *testing.T) {
	full := encodeInotifyEvents(rawInotifyEvent{wd: 1, mask: abiInModify, nameLen: 16, name: "memory.events"})
	cases := []struct {
		name string
		buf  []byte
	}{
		{name: "header cut short", buf: full[:10]},
		{name: "name longer than the remaining buffer", buf: full[:24]},
		{name: "trailing bytes after a complete record", buf: append(encodeInotifyEvents(rawInotifyEvent{wd: 1, mask: abiInModify}), 0, 0, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := parseInotifyEvents(tc.buf, 1); err == nil {
				t.Fatalf("parseInotifyEvents(%d bytes) = %+v, nil; want an error", len(tc.buf), got)
			}
		})
	}
}
