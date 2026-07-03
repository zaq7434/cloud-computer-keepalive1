package zte

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildCAGAuthBlobWithoutTemplate(t *testing.T) {
	params := &ConnectParams{
		Host:       "10.8.2.26",
		ProxySport: 5100,
		VMID:       "11111111-2222-3333-4444-555555555555",
	}

	blob, err := buildCAGAuthBlob(params, nil)
	if err != nil {
		t.Fatalf("buildCAGAuthBlob() error = %v", err)
	}
	if len(blob) != 220 {
		t.Fatalf("len(blob) = %d, want 220", len(blob))
	}
	if got := binary.LittleEndian.Uint32(blob[0:4]); got != 5100 {
		t.Fatalf("proxySport = %d, want 5100", got)
	}
	if got := blob[4:8]; !bytes.Equal(got, []byte{10, 8, 2, 26}) {
		t.Fatalf("target IP bytes = %x", got)
	}
	if got := string(blob[20:56]); got != params.VMID {
		t.Fatalf("vmId = %q, want %q", got, params.VMID)
	}
	if bytes.Equal(blob[60:188], make([]byte, 128)) {
		t.Fatal("random ticket block is all zero")
	}
	if blob[188] != 0x50 {
		t.Fatalf("tail marker = 0x%02x, want 0x50", blob[188])
	}
	if !bytes.Equal(blob[189:], make([]byte, 31)) {
		t.Fatalf("tail padding = %x", blob[189:])
	}
}

func TestBuildCAGAuthBlobPatchesTemplateVMID(t *testing.T) {
	template := make([]byte, 220)
	copy(template[20:56], []byte("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
	template[188] = 0x50
	params := &ConnectParams{
		Host:       "10.8.2.26",
		ProxySport: 5100,
		VMID:       "11111111-2222-3333-4444-555555555555",
	}

	blob, err := buildCAGAuthBlob(params, template)
	if err != nil {
		t.Fatalf("buildCAGAuthBlob() error = %v", err)
	}
	if got := string(blob[20:56]); got != params.VMID {
		t.Fatalf("vmId = %q, want %q", got, params.VMID)
	}
	if template[20] != 'a' {
		t.Fatal("template was modified in place")
	}
}
