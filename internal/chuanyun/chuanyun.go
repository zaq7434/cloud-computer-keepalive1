package chuanyun

import (
	"cloud-computer-keepalive/internal/logger"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	TrunkHello  = 3
	TrunkData   = 4
	TrunkSwitch = 5
	TrunkGBN    = 6

	FrameHeadSize = 24
)

var TrunkTypeNames = map[uint8]string{
	1: "Hello", 2: "Welcome", 3: "Hello", 4: "Data",
	5: "Switch", 6: "GBN", 7: "Reset",
}

var ChannelNames = map[uint64]string{
	0: "ctrl", 1: "main", 2: "display", 3: "inputs",
	4: "cursor", 5: "playback", 6: "record",
}

type Frame struct {
	PktType uint8
	Payload []byte
	Field1  uint64
	Field2  uint64
}

func FrameHeadPack(pktType uint8, payloadLen uint16, field1, field2 uint64) []byte {
	buf := make([]byte, FrameHeadSize)
	buf[0] = 0x01   // version
	buf[1] = pktType
	binary.LittleEndian.PutUint16(buf[2:4], payloadLen)
	binary.LittleEndian.PutUint32(buf[4:8], 0) // reserved
	binary.LittleEndian.PutUint64(buf[8:16], field1)
	binary.LittleEndian.PutUint64(buf[16:24], field2)
	return buf
}

func FrameHeadParse(data []byte) (ver, pktType uint8, payloadLen uint16, reserved uint32, field1, field2 uint64) {
	ver = data[0]
	pktType = data[1]
	payloadLen = binary.LittleEndian.Uint16(data[2:4])
	reserved = binary.LittleEndian.Uint32(data[4:8])
	field1 = binary.LittleEndian.Uint64(data[8:16])
	field2 = binary.LittleEndian.Uint64(data[16:24])
	return
}

func TrunkSwitchPack(targetCID, senderCID uint64, param uint32, switchReason uint8, extraID uint64, field1, field2 uint64) []byte {
	head := FrameHeadPack(TrunkSwitch, 32, field1, field2)
	if switchReason > 6 {
		switchReason = 6
	}
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint64(payload[0:8], targetCID)
	binary.LittleEndian.PutUint64(payload[8:16], senderCID)
	binary.LittleEndian.PutUint32(payload[16:20], param)
	payload[20] = switchReason
	// payload[21:24] padding (zeros)
	binary.LittleEndian.PutUint64(payload[24:32], extraID)
	return append(head, payload...)
}

func RecvExact(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func RecvTrunkFrame(conn net.Conn, timeout time.Duration) (*Frame, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))

	head, err := RecvExact(conn, FrameHeadSize)
	if err != nil {
		return nil, err
	}

	_, pktType, payloadLen, _, field1, field2 := FrameHeadParse(head)
	typeName := TrunkTypeNames[pktType]
	if typeName == "" {
		typeName = fmt.Sprintf("Type%d", pktType)
	}
	chName := ChannelNames[field2]
	if chName == "" {
		chName = fmt.Sprintf("ch%d", field2)
	}

	var payload []byte
	if payloadLen > 0 {
		payload, err = RecvExact(conn, int(payloadLen))
		if err != nil {
			payload = []byte{}
		}
	}

	logger.Infof("RECV %s(%d) %dB ch=%s", typeName, pktType, payloadLen, chName)
	if len(payload) > 0 {
		hexStr := fmt.Sprintf("%x", payload)
		if len(hexStr) > 80 {
			hexStr = hexStr[:80]
		}
		logger.Debugf("  f1=0x%x f2=0x%x payload=%s", field1, field2, hexStr)
	}

	return &Frame{
		PktType: pktType,
		Payload: payload,
		Field1:  field1,
		Field2:  field2,
	}, nil
}

func RecvAllFrames(conn net.Conn, timeout time.Duration, maxFrames int) []*Frame {
	var frames []*Frame
	for i := 0; i < maxFrames; i++ {
		frame, err := RecvTrunkFrame(conn, timeout)
		if err != nil {
			break
		}
		frames = append(frames, frame)
	}
	return frames
}
