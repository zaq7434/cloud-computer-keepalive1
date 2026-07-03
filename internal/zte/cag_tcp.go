package zte

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// DialCAGTCPTLS performs the ZTE CAG TCP pre-auth handshake and then upgrades
// the same socket to TLS. The SPICE tunnel add-link message is sent after this.
func DialCAGTCPTLS(ctx context.Context, opts CAGDialOptions) (net.Conn, *CAGSessionInfo, error) {
	if opts.Params == nil {
		return nil, nil, fmt.Errorf("missing connect params")
	}
	if opts.Address == "" {
		return nil, nil, fmt.Errorf("missing CAG address")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	authTemplate, err := parseAuthTemplate(opts.AuthTemplateHex)
	if err != nil {
		return nil, nil, err
	}

	dialer := net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", opts.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("TCP connect: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()

	deadline := time.Now().Add(opts.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	firstUDP, _, err := buildCAGAuthHeadPacket()
	if err != nil {
		return nil, nil, err
	}
	first := firstUDP[21:]
	if _, err := conn.Write(first); err != nil {
		return nil, nil, fmt.Errorf("send CAG TCP local-key: %w", err)
	}
	headAck, err := readCAGTCPPacket(conn, 50)
	if err != nil {
		return nil, nil, fmt.Errorf("read CAG TCP local-key ack: %w", err)
	}
	if len(headAck) < 50 || string(headAck[:4]) != "ZTEC" {
		return nil, nil, fmt.Errorf("invalid CAG TCP local-key ack")
	}
	conv := binary.LittleEndian.Uint32(headAck[14:18])

	second, err := buildCAGTCPAuthPacket(authTemplate, opts.Params)
	if err != nil {
		return nil, nil, err
	}
	if _, err := conn.Write(second); err != nil {
		return nil, nil, fmt.Errorf("send CAG TCP auth: %w", err)
	}
	authAck, err := readCAGTCPPacket(conn, 36)
	if err != nil {
		return nil, nil, fmt.Errorf("read CAG TCP auth ack: %w", err)
	}
	if len(authAck) < 8 || authAck[4] != 0x01 {
		prefixLen := 16
		if len(authAck) < prefixLen {
			prefixLen = len(authAck)
		}
		return nil, nil, fmt.Errorf("invalid CAG TCP auth ack: %x", authAck[:prefixLen])
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("CAG TCP TLS handshake: %w", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})

	closeOnError = false
	return tlsConn, &CAGSessionInfo{Conv: conv}, nil
}

func buildCAGTCPAuthPacket(template []byte, params *ConnectParams) ([]byte, error) {
	return buildCAGAuthBlob(params, template)
}

func readCAGTCPPacket(conn net.Conn, want int) ([]byte, error) {
	buf := make([]byte, want)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
