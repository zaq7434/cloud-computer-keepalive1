package zte

import "testing"

func TestParseConnectParams(t *testing.T) {
	raw := `-p 10072 -k abc123 -h 10.8.2.26 -f --vmid 11111111-2222-3333-4444-555555555555 --proxy-sport 5100 --pass-through eyJ0IjoiMSJ9%3D -t %22desktop%22 --accessToken token123 --vmip 10.0.0.1%3B192.168.1.2`
	params, err := ParseConnectParams(raw)
	if err != nil {
		t.Fatalf("ParseConnectParams() error = %v", err)
	}
	if params.Host != "10.8.2.26" || params.Port != 10072 {
		t.Fatalf("target = %s:%d", params.Host, params.Port)
	}
	if params.Key != "abc123" {
		t.Fatalf("Key = %q", params.Key)
	}
	if params.ProxySport != 5100 {
		t.Fatalf("ProxySport = %d", params.ProxySport)
	}
	if params.Args["-t"] != `"desktop"` {
		t.Fatalf("-t = %q", params.Args["-t"])
	}
	if params.VMIP != "10.0.0.1;192.168.1.2" {
		t.Fatalf("VMIP = %q", params.VMIP)
	}
}
