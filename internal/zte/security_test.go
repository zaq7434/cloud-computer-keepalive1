package zte

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

func TestDecodeSecurityParams(t *testing.T) {
	plain := []byte(`{"result":"0","success":true}`)
	ciphertext := encryptForTest(t, plain)
	body := []byte(`{"ZTE_Security_Params":"` + hex.EncodeToString(ciphertext) + `"}`)

	got, err := DecodeSecurityParams(body)
	if err != nil {
		t.Fatalf("DecodeSecurityParams() error = %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("DecodeSecurityParams() = %q, want %q", got, plain)
	}
}

func TestEncodeSecurityParams(t *testing.T) {
	tests := []struct {
		name  string
		plain string
		want  string
	}{
		{
			name:  "empty request body",
			plain: "",
			want:  "B4A8D3307A6B1DFC9CE3A87211FEE4F5",
		},
		{
			name:  "getToken request body",
			plain: `{"clienttype":0,"hardware":4,"nettype":2,"ostype":1}`,
			want:  "B08102A05BB2CD93BB3C466BA39B10EA752158A62574071124D2023277A37AA386ACFA11B8EE9887F39B400C6FBBC5845651914B3A30D3DAC138A48CF30AEB55",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeSecurityParams([]byte(tt.plain))
			if err != nil {
				t.Fatalf("EncodeSecurityParams() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("EncodeSecurityParams() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEncodeVDIPassword(t *testing.T) {
	got, err := EncodeVDIPassword("11111111-2222-3333-4444-55555555555500000000")
	if err != nil {
		t.Fatalf("EncodeVDIPassword() error = %v", err)
	}
	want := "g6vbC77ZD6CH71Ht797bfsT0lb7h6ZrLgOILA6SdIpio6FqXEvefkPPg9KXDALqT"
	if got != want {
		t.Fatalf("EncodeVDIPassword() = %q, want %q", got, want)
	}
}

func TestDecodeConnectString(t *testing.T) {
	want := "-p 10072 -h 10.8.2.26 --vmid test"
	connectStr := encodeConnectStringForTest(t, want)
	got, err := DecodeConnectString(connectStr)
	if err != nil {
		t.Fatalf("DecodeConnectString() error = %v", err)
	}
	if got != want {
		t.Fatalf("DecodeConnectString() = %q, want %q", got, want)
	}
}

func encryptForTest(t *testing.T, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher([]byte(securityKey))
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, []byte(securityIV)).CryptBlocks(out, padded)
	return out
}

func encodeConnectStringForTest(t *testing.T, plain string) string {
	t.Helper()
	block, err := aes.NewCipher([]byte(vdiKey))
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad([]byte(plain), aes.BlockSize)
	out := make([]byte, len(padded))
	for start := 0; start < len(padded); start += aes.BlockSize {
		block.Encrypt(out[start:start+aes.BlockSize], padded[start:start+aes.BlockSize])
	}
	return hex.EncodeToString(out)
}
