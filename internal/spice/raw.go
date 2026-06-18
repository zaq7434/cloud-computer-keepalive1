package spice

import (
	"bytes"
	"cloud-computer-keepalive/internal/logger"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type RawHandshakeResult struct {
	SpiceSessionID uint32
	OK             bool
}

var lastRawSerial uint32
var lastRawSuffix []byte

type RawState struct {
	LastSerial uint32
	LastSuffix []byte
	NextSerial uint32
}

func RawMainHandshake(conn net.Conn, key, vmid string, linkUUID []byte, traceID, spanID string) *RawHandshakeResult {
	state := &RawState{}
	logger.Info("Raw SPICE main channel link...")
	link := buildZTERawMainREDQ(key, vmid, linkUUID, traceID, spanID)
	if _, err := conn.Write(link); err != nil {
		logger.Errorf("Raw SPICE send REDQ failed: %v", err)
		return &RawHandshakeResult{}
	}

	reply, err := readRawLinkReply(conn, 8*time.Second)
	if err != nil {
		logger.Errorf("Raw SPICE read link reply failed: %v", err)
		return &RawHandshakeResult{}
	}
	pkOff := bytes.Index(reply, []byte{0x30, 0x81, 0x9f, 0x30, 0x0d})
	if pkOff < 0 {
		pkOff = bytes.Index(reply, []byte{0x30, 0x81})
	}
	if pkOff < 0 {
		logger.Error("Raw SPICE link reply has no RSA key")
		return &RawHandshakeResult{}
	}
	end := pkOff + 162
	if end > len(reply) {
		end = len(reply)
	}
	parsedKey, err := x509.ParsePKIXPublicKey(reply[pkOff:end])
	if err != nil {
		logger.Errorf("Raw SPICE parse RSA key failed: %v", err)
		return &RawHandshakeResult{}
	}
	pub, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		logger.Error("Raw SPICE link RSA key has unexpected type")
		return &RawHandshakeResult{}
	}
	_ = pub

	// ZTE's raw SPICE tunnel advertises the normal RSA link reply, but the
	// official client answers with a 128-byte zero ticket and no auth-type
	// prefix. Sending the regular SPICE auth type leaves the server stream
	// misaligned: auth can appear to succeed, then main init is closed.
	ticket := make([]byte, 128)
	if _, err := conn.Write(ticket); err != nil {
		logger.Errorf("Raw SPICE send ticket failed: %v", err)
		return &RawHandshakeResult{}
	}

	result := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.ReadFull(conn, result); err != nil {
		logger.Errorf("Raw SPICE read auth result failed: %v", err)
		return &RawHandshakeResult{}
	}
	if code := binary.LittleEndian.Uint32(result); code != 0 {
		logger.Errorf("Raw SPICE auth failed: result=%d", code)
		return &RawHandshakeResult{}
	}
	logger.Info("Raw SPICE main auth success")

	var spiceSessionID uint32
	for i := 0; i < 15; i++ {
		msgType, payload, err := state.ReadMessage(conn, 2*time.Second)
		if err != nil {
			break
		}
		logger.Debugf("Raw SPICE recv msg=0x%02x len=%d", msgType, len(payload))
		if msgType == 0x67 && len(payload) >= 10 {
			logger.Debugf("Raw SPICE MAIN_INIT payload head=%x", payload[:16])
			spiceSessionID = zteMainInitConnectionID(payload)
			logger.Infof("Raw SPICE MAIN_INIT session=0x%s", logger.Mask(fmt.Sprintf("%08x", spiceSessionID), 4))
			if d, ok := conn.(interface{ DiscardReadBuffer() }); ok {
				d.DiscardReadBuffer()
			}
			break
		}
		state.AutoReply(conn, msgType, payload)
	}
	if spiceSessionID == 0 {
		logger.Error("Raw SPICE MAIN_INIT not received")
		return &RawHandshakeResult{}
	}

	attach, _ := hexDecode("680000000000")
	attachSent := false
	for i := 0; i < 4; i++ {
		msgType, payload, err := state.ReadMessage(conn, 2*time.Second)
		if err != nil {
			break
		}
		logger.Debugf("Raw SPICE recv pre-init msg=0x%02x serial=%d len=%d", msgType, state.LastSerial, len(payload))
		if msgType == 0x04 {
			if state.LastSerial == 3 || i == 3 {
				_, _ = state.WriteMessage(conn, state.LastSerial, attach)
				attachSent = true
				break
			}
			continue
		}
		state.AutoReply(conn, msgType, payload)
	}
	if !attachSent {
		_, _ = conn.Write(append(rawMessageWithPrefix(3, attach), make([]byte, 5)...))
	}

	clientInfo, _ := hexDecode("72000800000000000000000100000001000000")
	terminalInfo := buildTerminalInfoMessage()
	_, _ = conn.Write(rawMessageWithPrefix(1, clientInfo))
	_, _ = conn.Write(rawMessageWithPrefix(2, terminalInfo))
	logger.Info("Raw SPICE sent client info + ATTACH_CHANNELS")
	initOK := false
	for i := 0; i < 5; i++ {
		msgType, payload, err := state.ReadMessage(conn, 1*time.Second)
		if err != nil {
			break
		}
		logger.Debugf("Raw SPICE recv init msg=0x%02x len=%d", msgType, len(payload))
		if msgType != 0x04 {
			state.AutoReply(conn, msgType, payload)
		}
		if msgType == 0x68 {
			initOK = true
		}
		if msgType == 0x73 {
			initOK = true
			break
		}
	}
	if !initOK {
		logger.Error("Raw SPICE init did not reach CHANNELS_LIST/info")
		return &RawHandshakeResult{}
	}
	return &RawHandshakeResult{SpiceSessionID: spiceSessionID, OK: true}
}

func BuildRawTicket(linkReply []byte) ([]byte, error) {
	pkOff := bytes.Index(linkReply, []byte{0x30, 0x82})
	if pkOff < 0 {
		pkOff = bytes.Index(linkReply, []byte{0x30, 0x81})
	}
	if pkOff < 0 {
		return nil, fmt.Errorf("raw SPICE link reply has no RSA key")
	}
	end := pkOff + derLength(linkReply[pkOff:])
	if end <= pkOff || end > len(linkReply) {
		end = len(linkReply)
	}
	parsedKey, err := x509.ParsePKIXPublicKey(linkReply[pkOff:end])
	if err != nil {
		return nil, err
	}
	pub, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("raw SPICE link RSA key has unexpected type")
	}
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, []byte{}, nil)
}

func derLength(der []byte) int {
	if len(der) < 2 || der[0] != 0x30 {
		return 0
	}
	if der[1]&0x80 == 0 {
		return int(der[1]) + 2
	}
	n := int(der[1] & 0x7f)
	if n == 0 || n > 4 || len(der) < 2+n {
		return 0
	}
	l := 0
	for i := 0; i < n; i++ {
		l = (l << 8) | int(der[2+i])
	}
	return 2 + n + l
}

func zteMainInitConnectionID(payload []byte) uint32 {
	marker := []byte{0x02, 0x00, 0x00, 0x00, 0x01}
	if idx := bytes.Index(payload, marker); idx >= 4 {
		return binary.LittleEndian.Uint32(payload[idx-4 : idx])
	}
	if len(payload) >= 7 {
		return binary.LittleEndian.Uint32(payload[3:7])
	}
	return 0
}

func buildRawREDQ(channelType uint8, channelID uint8, connectionID uint32) []byte {
	redq := make([]byte, 0, 42)
	redq = append(redq, []byte("REDQ")...)
	redq = appendU32LE(redq, 2)
	redq = appendU32LE(redq, 2)
	redq = appendU32LE(redq, 26)
	redq = appendU32LE(redq, connectionID)
	redq = append(redq, channelType, channelID)
	redq = appendU32LE(redq, 1)
	redq = appendU32LE(redq, 1)
	redq = appendU32LE(redq, 18)
	redq = appendU32LE(redq, 0x00000009)
	redq = appendU32LE(redq, 0x0000000f)
	return redq
}

func buildZTERawMainREDQ(key, vmid string, linkUUID []byte, traceID, spanID string) []byte {
	if len(linkUUID) != 16 {
		linkUUID = make([]byte, 16)
		_, _ = rand.Read(linkUUID)
	}
	redq := make([]byte, 729)
	copy(redq[0:4], []byte("REDQ"))
	binary.LittleEndian.PutUint32(redq[4:8], 2)
	binary.LittleEndian.PutUint32(redq[8:12], 2)
	binary.LittleEndian.PutUint32(redq[12:16], 713)
	redq[20] = 1
	binary.LittleEndian.PutUint32(redq[22:26], 1)
	binary.LittleEndian.PutUint32(redq[26:30], 1)
	binary.LittleEndian.PutUint32(redq[30:34], 705)
	binary.LittleEndian.PutUint32(redq[42:46], 0x1400)
	binary.LittleEndian.PutUint32(redq[46:50], 0x10000)
	copyCString(redq[50:95], key+vmid)
	copy(redq[95:111], linkUUID)
	copy(redq[127:143], terminalGUIDBytes())
	copyCString(redq[159:192], traceID)
	copyCString(redq[192:209], spanID)
	binary.LittleEndian.PutUint32(redq[717:721], 0x800)
	binary.LittleEndian.PutUint32(redq[721:725], 0x232900)
	return redq
}

func BuildZTERawChannelREDQ(key, vmid string, linkUUID []byte, traceID, spanID string, connectionID uint32, channelType, channelID uint8) []byte {
	length := 725
	size := uint32(709)
	capCount := uint32(0)
	caps := []uint32{0x800}

	switch channelType {
	case 2:
		length = 733
		size = 717
		capCount = 2
		caps = []uint32{0xa00, 0xffc30dec, 0x48}
	case 5:
		length = 729
		size = 713
		capCount = 1
		caps = []uint32{0x800, 0x0e}
	case 6:
		length = 729
		size = 713
		capCount = 1
		caps = []uint32{0x800, 0x07}
	}

	redq := make([]byte, length)
	copy(redq[0:4], []byte("REDQ"))
	binary.LittleEndian.PutUint32(redq[4:8], 2)
	binary.LittleEndian.PutUint32(redq[8:12], 2)
	binary.LittleEndian.PutUint32(redq[12:16], size)
	binary.LittleEndian.PutUint32(redq[16:20], connectionID)
	redq[20] = channelType
	redq[21] = channelID
	binary.LittleEndian.PutUint32(redq[22:26], 1)
	binary.LittleEndian.PutUint32(redq[26:30], capCount)
	binary.LittleEndian.PutUint32(redq[30:34], 705)
	binary.LittleEndian.PutUint32(redq[42:46], 0x1400)
	binary.LittleEndian.PutUint32(redq[46:50], 0x10000)
	copyCString(redq[50:95], key+vmid)
	copy(redq[95:111], linkUUID)
	copyCString(redq[159:192], traceID)
	copyCString(redq[192:209], spanID)

	capOff := length - len(caps)*4
	for i, capValue := range caps {
		binary.LittleEndian.PutUint32(redq[capOff+i*4:capOff+i*4+4], capValue)
	}
	return redq
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

func terminalGUIDBytes() []byte {
	// 31BF5444-86E0-4D5D-B1AB-A42FFBAC72C9, encoded as Windows GUID bytes.
	return []byte{0x44, 0x54, 0xbf, 0x31, 0xe0, 0x86, 0x5d, 0x4d, 0xb1, 0xab, 0xa4, 0x2f, 0xfb, 0xac, 0x72, 0xc9}
}

func buildTerminalInfoMessage() []byte {
	msg := make([]byte, 68)
	binary.LittleEndian.PutUint16(msg[0:2], 0x7c)
	binary.LittleEndian.PutUint32(msg[2:6], 57)
	copy(msg[11:], []byte("31BF5444-86E0-4D5D-B1AB-A42FFBAC72C9"))
	return msg
}

func readRawLinkReply(conn net.Conn, timeout time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	head := make([]byte, 16)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if !bytes.Equal(head[:4], []byte("REDQ")) {
		return nil, fmt.Errorf("invalid REDQ magic: %x", head[:4])
	}
	size := binary.LittleEndian.Uint32(head[12:16])
	if size > 4096 {
		return nil, fmt.Errorf("invalid REDQ reply size %d", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(head, body...), nil
}

func ReadRawMessage(conn net.Conn, timeout time.Duration) (uint16, []byte, error) {
	state := &RawState{LastSerial: lastRawSerial, LastSuffix: lastRawSuffix}
	msgType, payload, err := state.ReadMessage(conn, timeout)
	lastRawSerial = state.LastSerial
	lastRawSuffix = state.LastSuffix
	return msgType, payload, err
}

func (s *RawState) ReadMessage(conn net.Conn, timeout time.Duration) (uint16, []byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	head := make([]byte, 6)
	hasZTEPrefix := false
	if _, err := io.ReadFull(conn, head); err != nil {
		return 0, nil, err
	}
	msgType := binary.LittleEndian.Uint16(head[0:2])
	size := binary.LittleEndian.Uint32(head[2:6])
	if size == 0 {
		serial := binary.LittleEndian.Uint32(head[0:4])
		prefixTail := make([]byte, 2)
		if _, err := io.ReadFull(conn, prefixTail); err != nil {
			return 0, nil, err
		}
		if _, err := io.ReadFull(conn, head); err != nil {
			return 0, nil, err
		}
		msgType = binary.LittleEndian.Uint16(head[0:2])
		size = binary.LittleEndian.Uint32(head[2:6])
		s.LastSerial = serial
		s.LastSuffix = nil
		hasZTEPrefix = true
	}
	if size > 1<<20 {
		return 0, nil, fmt.Errorf("raw SPICE message too large: %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	if hasZTEPrefix {
		if t, ok := conn.(interface{ TakeReadBufferN(int) []byte }); ok {
			s.LastSuffix = t.TakeReadBufferN(5)
		}
	}
	return msgType, payload, nil
}

func RawAutoReply(conn net.Conn, msgType uint16, payload []byte) bool {
	state := &RawState{LastSerial: lastRawSerial, LastSuffix: lastRawSuffix}
	ok := state.AutoReply(conn, msgType, payload)
	lastRawSerial = state.LastSerial
	lastRawSuffix = state.LastSuffix
	return ok
}

func (s *RawState) AutoReply(conn net.Conn, msgType uint16, payload []byte) bool {
	switch msgType {
	case 0x04:
		pong := make([]byte, 6+len(payload))
		binary.LittleEndian.PutUint16(pong[0:2], 0x03)
		binary.LittleEndian.PutUint32(pong[2:6], uint32(len(payload)))
		copy(pong[6:], payload)
		_, _ = s.WriteMessage(conn, s.LastSerial, pong)
		return true
	case 0x03:
		var generation uint32
		if len(payload) >= 4 {
			generation = binary.LittleEndian.Uint32(payload[:4])
		}
		ack := make([]byte, 10)
		binary.LittleEndian.PutUint16(ack[0:2], 0x01)
		binary.LittleEndian.PutUint32(ack[2:6], 4)
		binary.LittleEndian.PutUint32(ack[6:10], generation)
		_, _ = s.WriteMessage(conn, s.LastSerial, ack)
		return true
	case 0x74:
		reply := make([]byte, 7)
		binary.LittleEndian.PutUint16(reply[0:2], 0x79)
		binary.LittleEndian.PutUint32(reply[2:6], 1)
		if _, err := s.WriteMessage(conn, s.nextSerial(), reply); err == nil {
			return true
		}
		return false
	}
	return false
}

func (s *RawState) WriteMessage(conn net.Conn, serial uint32, msg []byte) (int, error) {
	return conn.Write(append(rawMessageWithPrefix(serial, msg), s.LastSuffix...))
}

func (s *RawState) nextSerial() uint32 {
	if s.NextSerial == 0 {
		s.NextSerial = 4
	}
	serial := s.NextSerial
	s.NextSerial++
	return serial
}

func WriteRawMessage(conn net.Conn, serial uint32, msg []byte) (int, error) {
	return conn.Write(rawMessageWithPrefix(serial, msg))
}

func BuildZTERawDisplayInit() []byte {
	msg, _ := hexDecode("65001300000000000000000100004001000000000100fc5f000000000003")
	return msg
}

func BuildZTERawInputInit() []byte {
	msg, _ := hexDecode("67000200000000000000000200")
	return msg
}

func rawMessageWithPrefix(serial uint32, msg []byte) []byte {
	out := make([]byte, 8+len(msg))
	binary.LittleEndian.PutUint32(out[0:4], serial)
	copy(out[8:], msg)
	return out
}
