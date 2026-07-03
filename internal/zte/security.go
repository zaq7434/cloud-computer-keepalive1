package zte

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	securityKey = "56Acf4c3498fD4c5a0B1fb26947e2daB"
	securityIV  = "3498fD4c5a0B1fbA"
	vdiKey      = "3fec8a54-7e49-48"
)

type securityEnvelope struct {
	Params string `json:"ZTE_Security_Params"`
}

func DecodeSecurityParams(body []byte) ([]byte, error) {
	var env securityEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("parse security envelope: %w", err)
	}
	if env.Params == "" {
		return body, nil
	}

	ciphertext, err := hex.DecodeString(env.Params)
	if err != nil {
		return nil, fmt.Errorf("decode security params hex: %w", err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid security params length: %d", len(ciphertext))
	}

	block, err := aes.NewCipher([]byte(securityKey))
	if err != nil {
		return nil, fmt.Errorf("init aes: %w", err)
	}

	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, []byte(securityIV)).CryptBlocks(plain, ciphertext)

	plain, err = pkcs7Unpad(plain, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func DecodeSecurityJSON(body []byte) (map[string]any, error) {
	plain, err := DecodeSecurityParams(body)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(plain, &result); err != nil {
		return nil, fmt.Errorf("parse decoded security json: %w (body: %s)", err, string(plain))
	}
	return result, nil
}

func EncodeSecurityParams(plaintext []byte) (string, error) {
	block, err := aes.NewCipher([]byte(securityKey))
	if err != nil {
		return "", fmt.Errorf("init aes: %w", err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, []byte(securityIV)).CryptBlocks(ciphertext, padded)
	return strings.ToUpper(hex.EncodeToString(ciphertext)), nil
}

func EncodeVDIPassword(password string) (string, error) {
	block, err := aes.NewCipher([]byte(vdiKey))
	if err != nil {
		return "", fmt.Errorf("init vdi aes: %w", err)
	}
	plain := pkcs7Pad([]byte(password), aes.BlockSize)
	ciphertext := make([]byte, len(plain))
	for start := 0; start < len(plain); start += aes.BlockSize {
		block.Encrypt(ciphertext[start:start+aes.BlockSize], plain[start:start+aes.BlockSize])
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecodeConnectString(connectStr string) (string, error) {
	ciphertext, err := hex.DecodeString(connectStr)
	if err != nil {
		return "", fmt.Errorf("decode connectStr hex: %w", err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("invalid connectStr length: %d", len(ciphertext))
	}
	block, err := aes.NewCipher([]byte(vdiKey))
	if err != nil {
		return "", fmt.Errorf("init vdi aes: %w", err)
	}
	plain := make([]byte, len(ciphertext))
	for start := 0; start < len(ciphertext); start += aes.BlockSize {
		block.Decrypt(plain[start:start+aes.BlockSize], ciphertext[start:start+aes.BlockSize])
	}
	plain, err = pkcs7Unpad(plain, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("unpad connectStr: %w", err)
	}
	return string(plain), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid pkcs7 data length: %d", len(data))
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, fmt.Errorf("invalid pkcs7 padding: %d", pad)
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("invalid pkcs7 padding bytes")
		}
	}
	return data[:len(data)-pad], nil
}
