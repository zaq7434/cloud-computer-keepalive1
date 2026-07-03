package zte

import (
	"cloud-computer-keepalive/internal/logger"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	cagProxyDataCmd      = 0x0a
	cagProxyAddLinkCmd   = 0x1a
	cagProxyCloseLinkCmd = 0x2a
	cagProxyPayloadMax   = 0xffff
)

type CAGProxyConn struct {
	net.Conn
	linkID     byte
	linkUUID   []byte
	traceID    string
	spanID     string
	redqSpanID string
	rbuf       []byte
}

func OpenCAGProxyLink(ctx context.Context, conn net.Conn, params *ConnectParams, linkID byte) (*CAGProxyConn, error) {
	return OpenCAGProxyLinkWithTrace(ctx, conn, params, linkID, randomHex(16), randomHex(8))
}

func OpenCAGProxyLinkWithTrace(ctx context.Context, conn net.Conn, params *ConnectParams, linkID byte, traceID, spanID string) (*CAGProxyConn, error) {
	if params == nil {
		return nil, fmt.Errorf("missing connect params")
	}
	if linkID == 0 {
		linkID = 1
	}
	linkUUID := newZTELinkUUID()
	if traceID == "" {
		traceID = randomHex(16)
	}
	if spanID == "" {
		spanID = randomHex(8)
	}
	redqSpanID := randomHex(8)
	packet, err := buildCAGProxyAddLinkPacket(params, linkID, linkUUID, traceID, spanID)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("send CAG proxy add-link: %w", err)
	}
	logger.Debugf("ZTE CAG proxy send cmd=0x%02x link=%d len=%d head=%s", cagProxyAddLinkCmd, linkID, len(packet)-4, hexPrefix(packet, 80))
	_ = conn.SetWriteDeadline(time.Time{})
	return &CAGProxyConn{Conn: conn, linkID: linkID, linkUUID: linkUUID, traceID: traceID, spanID: spanID, redqSpanID: redqSpanID}, nil
}

func (c *CAGProxyConn) LinkUUID() []byte {
	return append([]byte(nil), c.linkUUID...)
}

func (c *CAGProxyConn) TraceID() string { return c.traceID }

func (c *CAGProxyConn) SpanID() string { return c.spanID }

func (c *CAGProxyConn) REDQSpanID() string { return c.redqSpanID }

func (c *CAGProxyConn) DiscardReadBuffer() {
	c.rbuf = nil
}

func (c *CAGProxyConn) TakeReadBuffer() []byte {
	out := append([]byte(nil), c.rbuf...)
	c.rbuf = nil
	return out
}

func (c *CAGProxyConn) TakeReadBufferN(n int) []byte {
	if n <= 0 || len(c.rbuf) == 0 {
		return nil
	}
	if n > len(c.rbuf) {
		n = len(c.rbuf)
	}
	out := append([]byte(nil), c.rbuf[:n]...)
	c.rbuf = c.rbuf[n:]
	return out
}

func (c *CAGProxyConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		head := make([]byte, 4)
		if _, err := io.ReadFull(c.Conn, head); err != nil {
			return 0, err
		}
		cmd := head[0]
		linkID := head[1]
		n := int(binary.LittleEndian.Uint16(head[2:4]))
		logger.Debugf("ZTE CAG proxy recv cmd=0x%02x link=%d len=%d", cmd, linkID, n)
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.Conn, payload); err != nil {
			return 0, err
		}
		if linkID != c.linkID {
			continue
		}
		switch cmd {
		case cagProxyDataCmd:
			c.rbuf = payload
		case cagProxyCloseLinkCmd:
			return 0, io.EOF
		default:
			if cmd&0x0f == cagProxyDataCmd {
				c.rbuf = payload
			}
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *CAGProxyConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > cagProxyPayloadMax {
			n = cagProxyPayloadMax
		}
		frame := make([]byte, 4+n)
		frame[0] = cagProxyDataCmd
		frame[1] = c.linkID
		binary.LittleEndian.PutUint16(frame[2:4], uint16(n))
		copy(frame[4:], p[:n])
		logger.Debugf("ZTE CAG proxy send cmd=0x%02x link=%d len=%d head=%s", cagProxyDataCmd, c.linkID, n, hexPrefix(frame, 80))
		if _, err := c.Conn.Write(frame); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func buildCAGProxyAddLinkPacket(params *ConnectParams, linkID byte, linkUUID []byte, traceID, spanID string) ([]byte, error) {
	addr, err := netip.ParseAddr(params.Host)
	if err != nil {
		return nil, fmt.Errorf("parse CAG target host %q: %w", params.Host, err)
	}
	if !addr.Is4() {
		return nil, fmt.Errorf("CAG proxy add-link currently supports IPv4 target only: %s", params.Host)
	}
	packet := make([]byte, 4+0x9a)
	packet[0] = cagProxyAddLinkCmd
	packet[1] = linkID
	binary.LittleEndian.PutUint16(packet[2:4], 0x9a)

	payload := packet[4:]
	binary.LittleEndian.PutUint16(payload[0:2], uint16(params.Port))
	payload[2] = 1
	if linkID != 1 {
		payload[2] = 2
	}
	ip := addr.As4()
	payload[4] = ip[3]
	payload[5] = ip[2]
	payload[6] = ip[1]
	payload[7] = ip[0]
	payload[0x53] = 0x05 // QoS value used by the ZTE tunnel LinkInfo.
	if linkID == 1 {
		payload[0x54] = 1 // SPICE main channel type.
	}
	copyCString(payload[0x68:0x89], traceID)
	copyCString(payload[0x89:0x9a], spanID)
	return packet, nil
}

func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func newZTELinkUUID() []byte {
	linkUUID := make([]byte, 16)
	_, _ = rand.Read(linkUUID)
	linkUUID[7] = (linkUUID[7] & 0x0f) | 0x40
	linkUUID[8] = (linkUUID[8] & 0x3f) | 0x80
	return linkUUID
}

func copyCString(dst []byte, s string) {
	if len(dst) == 0 {
		return
	}
	n := copy(dst, []byte(s))
	if n < len(dst) {
		dst[n] = 0
	}
}

func hexPrefix(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	return hex.EncodeToString(b[:n])
}

func parseUUIDBytes(value string) ([]byte, error) {
	raw := strings.ReplaceAll(value, "-", "")
	if len(raw) != 32 {
		return nil, fmt.Errorf("invalid UUID %q", value)
	}
	out, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode UUID %q: %w", value, err)
	}
	return out, nil
}
