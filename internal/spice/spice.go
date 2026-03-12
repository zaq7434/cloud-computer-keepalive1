package spice

import (
	"bytes"
	"cloud-computer-keepalive/internal/chuanyun"
	"cloud-computer-keepalive/internal/logger"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const DataType uint8 = 0x01

func autoReply(conn net.Conn, sid uint64, frame *chuanyun.Frame) bool {
	if frame.PktType != DataType || len(frame.Payload) < 6 {
		return false
	}

	msgType := binary.LittleEndian.Uint16(frame.Payload[0:2])
	chName := chuanyun.ChannelNames[frame.Field2]
	if chName == "" {
		chName = fmt.Sprintf("ch%d", frame.Field2)
	}

	if msgType == 0x04 { // PING -> PONG
		pingData := frame.Payload[6:]
		pong := make([]byte, 6+len(pingData))
		binary.LittleEndian.PutUint16(pong[0:2], 0x03)
		binary.LittleEndian.PutUint32(pong[2:6], uint32(len(pingData)))
		copy(pong[6:], pingData)

		head := chuanyun.FrameHeadPack(DataType, uint16(len(pong)), sid, frame.Field2)
		conn.Write(append(head, pong...))
		logger.Debugf("  PING -> PONG (ch=%s)", chName)
		return true
	}

	if msgType == 0x03 { // SET_ACK -> ACK_SYNC
		var generation uint32
		if len(frame.Payload) >= 10 {
			generation = binary.LittleEndian.Uint32(frame.Payload[6:10])
		}
		ackSync := make([]byte, 10)
		binary.LittleEndian.PutUint16(ackSync[0:2], 0x01)
		binary.LittleEndian.PutUint32(ackSync[2:6], 4)
		binary.LittleEndian.PutUint32(ackSync[6:10], generation)

		head := chuanyun.FrameHeadPack(DataType, uint16(len(ackSync)), sid, frame.Field2)
		conn.Write(append(head, ackSync...))
		logger.Debugf("  SET_ACK -> ACK_SYNC (gen=%d, ch=%s)", generation, chName)
		return true
	}

	return false
}

func recvFrameAR(conn net.Conn, sid uint64, timeout time.Duration) *chuanyun.Frame {
	frame, err := chuanyun.RecvTrunkFrame(conn, timeout)
	if err != nil {
		return nil
	}
	autoReply(conn, sid, frame)
	return frame
}

func SpiceChannelAuth(conn net.Conn, sid uint64, channelID uint64, channelType uint8, connectionID uint32) bool {
	chName := chuanyun.ChannelNames[channelID]
	if chName == "" {
		chName = fmt.Sprintf("ch%d", channelID)
	}
	_ = chName

	// ExtInfo: fixed 22B, last byte = channel_type
	extInfoBase, _ := hexDecode("010013f300080000000000010820f1000101f2000104")
	extInfo := make([]byte, len(extInfoBase))
	copy(extInfo, extInfoBase)
	extInfo[len(extInfo)-1] = channelType

	// token + REDQ
	token := make([]byte, 16)
	rand.Read(token)

	var redq []byte
	if channelType == 1 || channelType == 2 || channelType == 5 || channelType == 6 {
		redq = make([]byte, 0, 42)
		redq = appendLE(redq, []byte("REDQ"))
		redq = appendU32LE(redq, 2)
		redq = appendU32LE(redq, 2)
		redq = appendU32LE(redq, 26)
		redq = appendU32LE(redq, connectionID)
		redq = append(redq, channelType, 0)
		redq = appendU32LE(redq, 1)
		redq = appendU32LE(redq, 1)
		redq = appendU32LE(redq, 18)
		redq = appendU32LE(redq, 0x00000009)
		redq = appendU32LE(redq, 0x0000000f)
	} else {
		redq = make([]byte, 0, 38)
		redq = appendLE(redq, []byte("REDQ"))
		redq = appendU32LE(redq, 2)
		redq = appendU32LE(redq, 2)
		redq = appendU32LE(redq, 22)
		redq = appendU32LE(redq, connectionID)
		redq = append(redq, channelType, 0)
		redq = appendU32LE(redq, 1)
		redq = appendU32LE(redq, 0)
		redq = appendU32LE(redq, 14)
		redq = appendU32LE(redq, 0x00000009)
	}

	tokenRedq := append(token, redq...)

	// Send ExtInfo + token+REDQ
	buf := chuanyun.FrameHeadPack(DataType, uint16(len(extInfo)), sid, channelID)
	buf = append(buf, extInfo...)
	buf = append(buf, chuanyun.FrameHeadPack(DataType, uint16(len(tokenRedq)), sid, channelID)...)
	buf = append(buf, tokenRedq...)
	conn.Write(buf)

	// Wait for REDQ reply
	for i := 0; i < 20; i++ {
		frame := recvFrameAR(conn, sid, 2*time.Second)
		if frame == nil {
			break
		}
		if frame.PktType == 2 {
			continue
		}
		if frame.Field2 != channelID {
			continue
		}
		if !bytes.Contains(frame.Payload, []byte("REDQ")) {
			continue
		}

		// Extract RSA public key
		pkOff := bytes.Index(frame.Payload, []byte{0x30, 0x81, 0x9f, 0x30, 0x0d})
		if pkOff < 0 {
			pkOff = bytes.Index(frame.Payload, []byte{0x30, 0x81})
		}
		if pkOff < 0 {
			return false
		}

		end := pkOff + 162
		if end > len(frame.Payload) {
			end = len(frame.Payload)
		}
		rsaKey, err := x509.ParsePKIXPublicKey(frame.Payload[pkOff:end])
		if err != nil {
			return false
		}
		pubKey, ok := rsaKey.(*rsa.PublicKey)
		if !ok {
			return false
		}

		// Send auth
		authType := make([]byte, 4)
		binary.LittleEndian.PutUint32(authType, 1)
		ticket, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, []byte{}, nil)
		if err != nil {
			return false
		}

		authBuf := chuanyun.FrameHeadPack(DataType, uint16(len(authType)), sid, channelID)
		authBuf = append(authBuf, authType...)
		authBuf = append(authBuf, chuanyun.FrameHeadPack(DataType, uint16(len(ticket)), sid, channelID)...)
		authBuf = append(authBuf, ticket...)
		conn.Write(authBuf)

		// Wait for auth result
		for j := 0; j < 10; j++ {
			rf := recvFrameAR(conn, sid, 2*time.Second)
			if rf == nil {
				break
			}
			if rf.PktType == 2 {
				continue
			}
			if rf.Field2 != channelID {
				continue
			}
			if len(rf.Payload) == 4 {
				result := binary.LittleEndian.Uint32(rf.Payload)
				return result == 0
			}
		}
		return false
	}
	return false
}

func connectSubChannels(conn net.Conn, sid uint64, spiceSessionID uint32) []uint64 {
	// Only connect display channel
	type subCh struct {
		channelID   uint64
		channelType uint8
	}
	subChannels := []subCh{{2, 2}} // display

	// Build all sub-channels' ExtInfo+REDQ, send at once
	var buf []byte
	for _, sc := range subChannels {
		buf = append(buf, buildChannelREDQ(sid, sc.channelID, sc.channelType, spiceSessionID)...)
	}
	conn.Write(buf)

	channelIDs := make([]uint64, len(subChannels))
	for i, sc := range subChannels {
		channelIDs[i] = sc.channelID
	}
	logger.Infof("SEND sub-channel ExtInfo+REDQ (%v)", channelIDs)

	// Collect REDQ responses and authenticate
	state := make(map[uint64]string)
	for _, sc := range subChannels {
		state[sc.channelID] = "redq"
	}
	var connected []uint64

	for i := 0; i < 60; i++ {
		allDone := true
		for _, s := range state {
			if s != "done" {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}

		frame := recvFrameAR(conn, sid, 2*time.Second)
		if frame == nil {
			break
		}
		if frame.PktType == 2 {
			continue
		}

		// Wait for REDQ reply
		if state[frame.Field2] == "redq" && bytes.Contains(frame.Payload, []byte("REDQ")) {
			pkOff := bytes.Index(frame.Payload, []byte{0x30, 0x81, 0x9f, 0x30, 0x0d})
			if pkOff < 0 {
				pkOff = bytes.Index(frame.Payload, []byte{0x30, 0x81})
			}
			if pkOff < 0 {
				state[frame.Field2] = "done"
				continue
			}
			end := pkOff + 162
			if end > len(frame.Payload) {
				end = len(frame.Payload)
			}
			rsaKey, err := x509.ParsePKIXPublicKey(frame.Payload[pkOff:end])
			if err != nil {
				state[frame.Field2] = "done"
				continue
			}
			pubKey, ok := rsaKey.(*rsa.PublicKey)
			if !ok {
				state[frame.Field2] = "done"
				continue
			}

			// Send auth immediately
			authType := make([]byte, 4)
			binary.LittleEndian.PutUint32(authType, 1)
			ticket, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, []byte{}, nil)
			if err != nil {
				state[frame.Field2] = "done"
				continue
			}

			authBuf := chuanyun.FrameHeadPack(DataType, 4, sid, frame.Field2)
			authBuf = append(authBuf, authType...)
			authBuf = append(authBuf, chuanyun.FrameHeadPack(DataType, uint16(len(ticket)), sid, frame.Field2)...)
			authBuf = append(authBuf, ticket...)
			conn.Write(authBuf)
			state[frame.Field2] = "auth"

			chName := chuanyun.ChannelNames[frame.Field2]
			if chName == "" {
				chName = fmt.Sprintf("ch%d", frame.Field2)
			}
			logger.Debugf("  %s: REDQ received, auth sent", chName)
			continue
		}

		// Wait for auth result
		if state[frame.Field2] == "auth" && len(frame.Payload) == 4 {
			result := binary.LittleEndian.Uint32(frame.Payload)
			chName := chuanyun.ChannelNames[frame.Field2]
			if chName == "" {
				chName = fmt.Sprintf("ch%d", frame.Field2)
			}
			if result == 0 {
				connected = append(connected, frame.Field2)
				logger.Infof("  %s channel auth success", chName)
			} else {
				logger.Errorf("  %s channel auth failed (result=%d)", chName, result)
			}
			state[frame.Field2] = "done"
			continue
		}
	}

	// Display init — send DISPLAY_INIT to trigger Surface creation
	hasDisplay := false
	for _, c := range connected {
		if c == 2 {
			hasDisplay = true
			break
		}
	}
	if hasDisplay {
		displayInit := make([]byte, 20)
		binary.LittleEndian.PutUint16(displayInit[0:2], 0x65)
		binary.LittleEndian.PutUint32(displayInit[2:6], 14)
		displayInit[6] = 1 // pixmap_cache_id
		binary.LittleEndian.PutUint64(displayInit[7:15], 0x1400000) // pixmap_cache_size (i64)
		displayInit[15] = 1 // glz_dictionary_id
		binary.LittleEndian.PutUint32(displayInit[16:20], 0x7ffc00) // glz_dictionary_window_size (i32)

		head := chuanyun.FrameHeadPack(DataType, uint16(len(displayInit)), sid, 2)
		conn.Write(append(head, displayInit...))
		logger.Info("  display: DISPLAY_INIT sent")

		// Consume display init messages
		for j := 0; j < 20; j++ {
			frame := recvFrameAR(conn, sid, 2*time.Second)
			if frame == nil {
				break
			}
			if frame.PktType == 2 {
				continue
			}
			if frame.Field2 != 2 || len(frame.Payload) < 6 {
				continue
			}
			msgType := binary.LittleEndian.Uint16(frame.Payload[0:2])
			if msgType == 0x66 { // MARK
				logger.Info("  display: MARK received (Surface created)")
				break
			}
		}
	}

	// Report failures
	for cid, s := range state {
		found := false
		for _, c := range connected {
			if c == cid {
				found = true
				break
			}
		}
		if !found && s == "done" {
			chName := chuanyun.ChannelNames[cid]
			if chName == "" {
				chName = fmt.Sprintf("ch%d", cid)
			}
			logger.Warnf("  channel not connected: %s", chName)
		}
	}

	return connected
}

type HandshakeResult struct {
	SessionID        uint64
	SpiceSessionID   uint32
	SpiceOK          bool
	ConnectedChannels []uint64
}

func SpiceHandshake(conn net.Conn) *HandshakeResult {
	// 1. Read Welcome to get session_id
	logger.Info("Reading session_id...")
	frame, err := chuanyun.RecvTrunkFrame(conn, 3*time.Second)
	if err != nil || frame == nil {
		return &HandshakeResult{}
	}
	sid := frame.Field1
	logger.Infof("session_id=0x%s", logger.Mask(fmt.Sprintf("%x", sid), 4))
	logger.Debugf("session_id=0x%x", sid)

	// 2. Main channel SPICE handshake
	logger.Info("Main channel SPICE handshake...")
	ok := SpiceChannelAuth(conn, sid, 1, 1, 0)
	if !ok {
		logger.Error("Main channel auth failed")
		return &HandshakeResult{SessionID: sid}
	}
	logger.Info("Main channel auth success")

	// 3. Read MAIN_INIT, extract spice_session_id
	var spiceSessionID uint32
	for i := 0; i < 15; i++ {
		frame := recvFrameAR(conn, sid, 2*time.Second)
		if frame == nil {
			break
		}
		if frame.PktType == 2 {
			continue
		}
		if len(frame.Payload) >= 10 && frame.Payload[0] == 0x67 && frame.Payload[1] == 0x00 {
			msgSize := binary.LittleEndian.Uint32(frame.Payload[2:6])
			if msgSize >= 4 {
				spiceSessionID = binary.LittleEndian.Uint32(frame.Payload[6:10])
				logger.Infof("MAIN_INIT spice_session_id=0x%s", logger.Mask(fmt.Sprintf("%08x", spiceSessionID), 4))
				logger.Debugf("MAIN_INIT spice_session_id=0x%08x", spiceSessionID)
			}
		}
	}

	if spiceSessionID == 0 {
		logger.Error("MAIN_INIT not received")
		return &HandshakeResult{SessionID: sid}
	}

	// 4. Send client response + ATTACH_CHANNELS
	clientInfo, _ := hexDecode("7200140000001000000064000000080000002008010000000000")
	attach, _ := hexDecode("680000000000")

	buf := chuanyun.FrameHeadPack(DataType, uint16(len(clientInfo)), sid, 1)
	buf = append(buf, clientInfo...)
	buf = append(buf, chuanyun.FrameHeadPack(DataType, uint16(len(attach)), sid, 1)...)
	buf = append(buf, attach...)
	conn.Write(buf)
	logger.Info("SEND client info + ATTACH_CHANNELS")

	// 5. Consume initial server messages (CHANNELS_LIST etc.)
	for i := 0; i < 10; i++ {
		frame := recvFrameAR(conn, sid, 2*time.Second)
		if frame == nil {
			break
		}
		if frame.PktType == 2 {
			continue
		}
		if frame.Field2 == 1 && len(frame.Payload) >= 6 {
			msgType := binary.LittleEndian.Uint16(frame.Payload[0:2])
			if msgType == 0x68 {
				logger.Info("CHANNELS_LIST received")
				break
			}
		}
	}

	// 6. Connect sub-channels
	connected := connectSubChannels(conn, sid, spiceSessionID)
	var names []string
	for _, c := range connected {
		name := chuanyun.ChannelNames[c]
		if name == "" {
			name = fmt.Sprintf("ch%d", c)
		}
		names = append(names, name)
	}
	logger.Infof("Sub-channels connected: %v", names)

	return &HandshakeResult{
		SessionID:        sid,
		SpiceSessionID:   spiceSessionID,
		SpiceOK:          true,
		ConnectedChannels: connected,
	}
}

// AutoReply exports the auto-reply logic for use in keepalive loop.
func AutoReply(conn net.Conn, sid uint64, frame *chuanyun.Frame) bool {
	return autoReply(conn, sid, frame)
}

// helpers

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + c - '0'
			case c >= 'a' && c <= 'f':
				v = v*16 + c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = v*16 + c - 'A' + 10
			}
		}
		b[i/2] = v
	}
	return b, nil
}

func appendLE(dst, src []byte) []byte {
	return append(dst, src...)
}

func appendU32LE(dst []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(dst, b...)
}

func buildChannelREDQ(sid, channelID uint64, channelType uint8, connectionID uint32) []byte {
	extInfoBase, _ := hexDecode("010013f300080000000000010820f1000101f2000104")
	extInfo := make([]byte, len(extInfoBase))
	copy(extInfo, extInfoBase)
	extInfo[len(extInfo)-1] = channelType

	token := make([]byte, 16)
	rand.Read(token)

	var redq []byte
	if channelType == 1 || channelType == 2 || channelType == 5 || channelType == 6 {
		redq = make([]byte, 0, 42)
		redq = appendLE(redq, []byte("REDQ"))
		redq = appendU32LE(redq, 2)
		redq = appendU32LE(redq, 2)
		redq = appendU32LE(redq, 26)
		redq = appendU32LE(redq, connectionID)
		redq = append(redq, channelType, 0)
		redq = appendU32LE(redq, 1)
		redq = appendU32LE(redq, 1)
		redq = appendU32LE(redq, 18)
		redq = appendU32LE(redq, 0x00000009)
		redq = appendU32LE(redq, 0x0000000f)
	} else {
		redq = make([]byte, 0, 38)
		redq = appendLE(redq, []byte("REDQ"))
		redq = appendU32LE(redq, 2)
		redq = appendU32LE(redq, 2)
		redq = appendU32LE(redq, 22)
		redq = appendU32LE(redq, connectionID)
		redq = append(redq, channelType, 0)
		redq = appendU32LE(redq, 1)
		redq = appendU32LE(redq, 0)
		redq = appendU32LE(redq, 14)
		redq = appendU32LE(redq, 0x00000009)
	}

	tokenRedq := append(token, redq...)

	buf := chuanyun.FrameHeadPack(DataType, uint16(len(extInfo)), sid, channelID)
	buf = append(buf, extInfo...)
	buf = append(buf, chuanyun.FrameHeadPack(DataType, uint16(len(tokenRedq)), sid, channelID)...)
	buf = append(buf, tokenRedq...)
	return buf
}
