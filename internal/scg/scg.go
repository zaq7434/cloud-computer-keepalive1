package scg

import (
	"cloud-computer-keepalive/internal/crypto"
	"cloud-computer-keepalive/internal/logger"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

func BuildAuthPacket(scAuthCode string, vmID string) ([]byte, error) {
	scBytes := []byte(scAuthCode)
	vmTail := []byte("|" + vmID)
	tlvValue := append(scBytes, vmTail...)
	tlvLength := len(tlvValue)

	// Build plaintext: version(2) + timestamp(8) + TLV_type(1) + TLV_length(2) + TLV_value
	plaintext := make([]byte, 0, 13+tlvLength)
	plaintext = append(plaintext, 0x00, 0x02) // version
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	plaintext = append(plaintext, ts...)
	plaintext = append(plaintext, 0x03) // TLV type
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(tlvLength))
	plaintext = append(plaintext, lenBuf...)
	plaintext = append(plaintext, tlvValue...)

	encrypted, err := crypto.AESCTREncrypt(plaintext)
	if err != nil {
		return nil, err
	}

	baseID := byte(len(encrypted) % 256)
	packet := make([]byte, 0, 2+len(encrypted))
	packet = append(packet, 0x01, baseID)
	packet = append(packet, encrypted...)
	return packet, nil
}

func ConnectSCG(scgIP, scgPort, scAuthCode, vmID string) (net.Conn, uint64, error) {
	authPacket, err := BuildAuthPacket(scAuthCode, vmID)
	if err != nil {
		return nil, 0, fmt.Errorf("build auth packet: %w", err)
	}
	logger.Infof("Auth packet: %d bytes (scAuthCode: %d chars)", len(authPacket), len(scAuthCode))

	addr := net.JoinHostPort(scgIP, scgPort)
	logger.Infof("Connecting SCG %s...", addr)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, 0, fmt.Errorf("TCP connect: %w", err)
	}
	logger.Info("TCP connected")

	if _, err := conn.Write(authPacket); err != nil {
		conn.Close()
		return nil, 0, fmt.Errorf("send auth packet: %w", err)
	}
	logger.Debug("Auth packet sent")

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 128)
	n, err := conn.Read(response)
	if err != nil {
		conn.Close()
		return nil, 0, fmt.Errorf("read auth response: %w", err)
	}
	response = response[:n]
	conn.SetReadDeadline(time.Time{})

	logger.Debugf("Response: %d bytes, hex=%x", n, response[:min(16, n)])

	if response[0] == 0x00 {
		sessionID := uint64(response[6])<<16 | uint64(response[7])<<8 | uint64(response[8])
		logger.Infof("Auth success! session=0x%s", logger.Mask(fmt.Sprintf("%06x", sessionID), 4))
		logger.Debugf("session_id=0x%06x", sessionID)

		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, 0, fmt.Errorf("TLS handshake: %w", err)
		}
		logger.Infof("TLS handshake ok: %s", tlsConn.ConnectionState().NegotiatedProtocol)

		return tlsConn, sessionID, nil
	} else if response[0] == 0x0b {
		conn.Close()
		return nil, 0, fmt.Errorf("auth downgrade (token expired or replay)")
	} else {
		conn.Close()
		return nil, 0, fmt.Errorf("auth failed: byte[0]=0x%02x", response[0])
	}
}
