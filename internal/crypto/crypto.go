package crypto

import (
	"cloud-computer-keepalive/internal/config"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
)

var (
	sohoRSAKey *rsa.PublicKey
	cemRSAKey  *rsa.PublicKey
)

func init() {
	var err error
	sohoRSAKey, err = parseRSAPublicKey(config.RSAPublicKeyB64)
	if err != nil {
		panic(fmt.Sprintf("parse SOHO RSA key: %v", err))
	}
	cemRSAKey, err = parseRSAPublicKey(config.CEMRSAPublicKeyB64)
	if err != nil {
		panic(fmt.Sprintf("parse CEM RSA key: %v", err))
	}
}

func parseRSAPublicKey(b64 string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaPub, nil
}

// rsaEncryptBlock performs textbook RSA (no padding) on a single block: c = m^e mod n
// Returns raw encrypted bytes, zero-padded to modulus byte length.
func rsaEncryptBlock(data []byte, key *rsa.PublicKey) []byte {
	m := new(big.Int).SetBytes(data)
	e := big.NewInt(int64(key.E))
	c := new(big.Int).Exp(m, e, key.N)

	modulusLen := (key.N.BitLen() + 7) / 8
	cBytes := c.Bytes()
	if len(cBytes) < modulusLen {
		padded := make([]byte, modulusLen)
		copy(padded[modulusLen-len(cBytes):], cBytes)
		cBytes = padded
	}
	return cBytes
}

// RSAEncrypt performs textbook RSA (no padding): c = m^e mod n
// Result is zero-padded to modulus byte length, then base64 encoded.
func RSAEncrypt(plaintext string) (string, error) {
	encrypted := rsaEncryptBlock([]byte(plaintext), sohoRSAKey)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// RSAEncryptChunked splits plaintext into 117-byte chunks and encrypts each
// with textbook RSA. Concatenated result is base64 encoded.
// Used when payload exceeds single RSA block size (128 bytes).
func RSAEncryptChunked(plaintext string) (string, error) {
	return RSAEncryptChunkedWithKey(plaintext, sohoRSAKey)
}

// RSAEncryptChunkedWithKey is like RSAEncryptChunked but uses the given key.
func RSAEncryptChunkedWithKey(plaintext string, key *rsa.PublicKey) (string, error) {
	data := []byte(plaintext)
	var encrypted []byte
	for i := 0; i < len(data); i += 117 {
		end := i + 117
		if end > len(data) {
			end = len(data)
		}
		encrypted = append(encrypted, rsaEncryptBlock(data[i:end], key)...)
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// RSAEncryptWithKey encrypts a single block using the given RSA key, returns base64.
func RSAEncryptWithKey(plaintext string, key *rsa.PublicKey) (string, error) {
	encrypted := rsaEncryptBlock([]byte(plaintext), key)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// ParseRSAPublicKey parses a base64-encoded DER RSA public key.
func ParseRSAPublicKey(b64 string) (*rsa.PublicKey, error) {
	return parseRSAPublicKey(b64)
}

// CEMRSAEncrypt performs RSA PKCS1v1.5 encryption, returns "{rsa}" + base64.
func CEMRSAEncrypt(plaintext string) (string, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, cemRSAKey, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return "{rsa}" + base64.StdEncoding.EncodeToString(encrypted), nil
}

// AESCTREncrypt encrypts with AES-128-CTR using custom counter format:
// counter = [lo_u64_LE (incrementing from 0xFEFEFEFEFEFEFEFE), hi_u64_LE (fixed 0xFEFEFEFEFEFEFEFE)]
func AESCTREncrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(config.AuthAESKey)
	if err != nil {
		return nil, err
	}

	numBlocks := (len(plaintext) + aes.BlockSize - 1) / aes.BlockSize
	keystream := make([]byte, 0, numBlocks*aes.BlockSize)
	counter := make([]byte, aes.BlockSize)
	encrypted := make([]byte, aes.BlockSize)

	for i := 0; i < numBlocks; i++ {
		binary.LittleEndian.PutUint64(counter[0:8], config.AuthCTRInit+uint64(i))
		binary.LittleEndian.PutUint64(counter[8:16], config.AuthCTRInit)
		block.Encrypt(encrypted, counter)
		keystream = append(keystream, encrypted...)
	}

	result := make([]byte, len(plaintext))
	for i := range plaintext {
		result[i] = plaintext[i] ^ keystream[i]
	}
	return result, nil
}
