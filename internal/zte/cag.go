package zte

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

type CAGSessionInfo struct {
	SynID []byte
	Conv  uint32
}

type CAGDialOptions struct {
	Address         string
	Params          *ConnectParams
	AuthTemplateHex string
	Timeout         time.Duration
}

func DialCAGKCP(ctx context.Context, opts CAGDialOptions) (net.Conn, *CAGSessionInfo, error) {
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

	remote, err := net.ResolveUDPAddr("udp", opts.Address)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = udpConn.Close()
		}
	}()

	deadline := time.Now().Add(opts.Timeout)
	_ = udpConn.SetDeadline(deadline)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		_ = udpConn.SetDeadline(ctxDeadline)
	}

	first, synID, err := buildCAGAuthHeadPacket()
	if err != nil {
		return nil, nil, err
	}
	if _, err := udpConn.WriteToUDP(first, remote); err != nil {
		return nil, nil, err
	}

	headAck, err := readCAGPacket(ctx, udpConn, remote, 0x07)
	if err != nil {
		return nil, nil, fmt.Errorf("wait CAG auth head ack: %w", err)
	}
	replySynID, conv, err := parseCAGAuthHeader(headAck)
	if err != nil {
		return nil, nil, err
	}
	if !equalBytes(synID, replySynID) {
		return nil, nil, fmt.Errorf("CAG auth head ack syn id mismatch")
	}

	second, err := buildCAGAuthPacket(authTemplate, synID, conv, opts.Params)
	if err != nil {
		return nil, nil, err
	}
	if _, err := udpConn.WriteToUDP(second, remote); err != nil {
		return nil, nil, err
	}
	if _, err := readCAGPacket(ctx, udpConn, remote, 0x09); err != nil {
		return nil, nil, fmt.Errorf("wait CAG auth ack: %w", err)
	}

	third := buildCAGSynPacket(synID, conv)
	if _, err := udpConn.WriteToUDP(third, remote); err != nil {
		return nil, nil, err
	}
	if _, err := readCAGPacket(ctx, udpConn, remote, 0x02); err != nil {
		return nil, nil, fmt.Errorf("wait CAG syn ack: %w", err)
	}
	_ = udpConn.SetDeadline(time.Time{})

	packetConn := newCAGPacketConn(udpConn, os.Getenv("CCK_ZTE_CAG_TRACE_DIR"))
	session, err := kcp.NewConn3(conv, remote, nil, 0, 0, packetConn)
	if err != nil {
		return nil, nil, err
	}
	session.SetNoDelay(1, 10, 2, 1)
	session.SetWindowSize(128, 512)
	session.SetMtu(1300)

	closeOnError = false
	return session, &CAGSessionInfo{SynID: append([]byte(nil), synID...), Conv: conv}, nil
}

func DialCAGTLS(ctx context.Context, opts CAGDialOptions) (net.Conn, *CAGSessionInfo, error) {
	conn, info, err := DialCAGKCP(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("CAG TLS handshake: %w", err)
	}
	return tlsConn, info, nil
}

func parseAuthTemplate(templateHex string) ([]byte, error) {
	if templateHex == "" {
		return nil, nil
	}
	template, err := hex.DecodeString(templateHex)
	if err != nil {
		return nil, fmt.Errorf("decode CAG auth template: %w", err)
	}
	if len(template) == 241 && template[0] == 0x08 {
		return append([]byte(nil), template...), nil
	}
	if len(template) == 220 {
		return append([]byte(nil), template...), nil
	}
	return nil, fmt.Errorf("invalid CAG auth template length %d", len(template))
}

func buildCAGAuthBlob(params *ConnectParams, template []byte) ([]byte, error) {
	if params == nil {
		return nil, fmt.Errorf("missing connect params")
	}
	if len(template) == 241 {
		template = template[21:]
	}
	if len(template) == 220 {
		blob := append([]byte(nil), template...)
		if len(params.VMID) == 36 {
			copy(blob[20:56], []byte(params.VMID))
		}
		return blob, nil
	}
	if len(template) != 0 {
		return nil, fmt.Errorf("invalid CAG auth template length %d", len(template))
	}

	ip := net.ParseIP(params.Host).To4()
	if ip == nil {
		return nil, fmt.Errorf("CAG auth blob requires IPv4 host: %s", params.Host)
	}
	if params.ProxySport <= 0 {
		return nil, fmt.Errorf("CAG auth blob requires proxySport")
	}
	if len(params.VMID) != 36 {
		return nil, fmt.Errorf("CAG auth blob requires 36-byte vmId")
	}

	blob := make([]byte, 220)
	binary.LittleEndian.PutUint32(blob[0:4], uint32(params.ProxySport))
	copy(blob[4:8], ip)
	copy(blob[20:56], []byte(params.VMID))
	fillRandom(blob[60:188])
	blob[188] = 0x50
	return blob, nil
}

func buildCAGAuthHeadPacket() ([]byte, []byte, error) {
	packet := make([]byte, 21+178)
	copy(packet[0:4], []byte{0x06, 0x00, 0x00, 0x80})
	synID := packet[11:15]
	if _, err := rand.Read(synID); err != nil {
		return nil, nil, err
	}

	payload := packet[21:]
	copy(payload[0:4], []byte("ZTEC"))
	binary.LittleEndian.PutUint16(payload[4:6], 0x00ac)
	binary.LittleEndian.PutUint32(payload[6:10], 101)
	fillRandom(payload[10:14])
	copy(payload[14:18], []byte{0xdc, 0x00, 0x00, 0x00})
	fillRandom(payload[18:38])
	copy(payload[38:42], []byte{0x07, 0x00, 0x0b, 0x0b})
	fillASCIIHex(payload[54:86])
	fillASCIIHex(payload[118:134])
	return packet, append([]byte(nil), synID...), nil
}

func buildCAGAuthPacket(template, synID []byte, conv uint32, params *ConnectParams) ([]byte, error) {
	if len(template) == 241 {
		packet := append([]byte(nil), template...)
		copy(packet[11:15], synID)
		binary.LittleEndian.PutUint32(packet[15:19], conv)
		return packet, nil
	}

	blob, err := buildCAGAuthBlob(params, template)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 21+len(blob))
	copy(packet[0:4], []byte{0x08, 0x00, 0x00, 0x80})
	copy(packet[11:15], synID)
	binary.LittleEndian.PutUint32(packet[15:19], conv)
	copy(packet[21:], blob)
	return packet, nil
}

func buildCAGSynPacket(synID []byte, conv uint32) []byte {
	packet := make([]byte, 21)
	copy(packet[0:4], []byte{0x01, 0x00, 0x00, 0x80})
	copy(packet[4:8], []byte{0x53, 0x01, 0x00, 0x22})
	copy(packet[11:15], synID)
	binary.LittleEndian.PutUint32(packet[15:19], conv)
	copy(packet[19:21], []byte{0x14, 0x05})
	return packet
}

func readCAGPacket(ctx context.Context, conn *net.UDPConn, remote *net.UDPAddr, packetType byte) ([]byte, error) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if from == nil || from.IP.String() != remote.IP.String() || from.Port != remote.Port {
			continue
		}
		if n >= 21 && buf[0] == packetType && buf[3] == 0x80 {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func parseCAGAuthHeader(packet []byte) ([]byte, uint32, error) {
	if len(packet) < 21 || packet[0] != 0x07 || packet[3] != 0x80 {
		return nil, 0, fmt.Errorf("invalid CAG auth head ack")
	}
	return append([]byte(nil), packet[11:15]...), binary.LittleEndian.Uint32(packet[15:19]), nil
}

func fillRandom(dst []byte) {
	if _, err := rand.Read(dst); err != nil {
		for i := range dst {
			dst[i] = byte(time.Now().UnixNano() >> (uint(i%8) * 8))
		}
	}
}

func fillASCIIHex(dst []byte) {
	raw := make([]byte, len(dst)/2)
	fillRandom(raw)
	hex.Encode(dst, raw)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

type cagPacketConn struct {
	net.PacketConn
	dir string
	seq atomic.Uint64
}

func newCAGPacketConn(conn net.PacketConn, dir string) net.PacketConn {
	if dir != "" {
		_ = os.MkdirAll(dir, 0700)
	}
	return &cagPacketConn{PacketConn: conn, dir: dir}
}

func (c *cagPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if n > 0 {
			c.write("rx-raw", p[:n])
			if n >= 24 && p[4] == 0x85 {
				c.sendMTUAck(p[:n], addr)
				continue
			}
			if n >= 24 && p[4] >= 0x81 && p[4] <= 0x84 {
				p[4] -= 0x30
				c.write("rx-kcp", p[:n])
			}
		}
		return n, addr, err
	}
}

func (c *cagPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := p
	if len(p) >= 24 && p[4] >= 0x51 && p[4] <= 0x54 {
		out = append([]byte(nil), p...)
		out[4] += 0x30
	}
	if len(out) > 0 {
		c.write("tx-raw", out)
	}
	return c.PacketConn.WriteTo(out, addr)
}

func (c *cagPacketConn) write(direction string, data []byte) {
	if c.dir == "" {
		return
	}
	seq := c.seq.Add(1)
	name := fmt.Sprintf("%06d-%s-%d.bin", seq, direction, len(data))
	_ = os.WriteFile(filepath.Join(c.dir, name), append([]byte(nil), data...), 0600)
}

func (c *cagPacketConn) sendMTUAck(packet []byte, addr net.Addr) {
	if len(packet) < 24 {
		return
	}
	ack := make([]byte, 24)
	copy(ack[0:4], packet[0:4])
	ack[4] = 0x86
	copy(ack[5:20], packet[5:20])
	c.write("tx-mtuack", ack)
	_, _ = c.PacketConn.WriteTo(ack, addr)
}
