package zte

import (
	"cloud-computer-keepalive/internal/logger"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type CAGMux struct {
	conn   net.Conn
	writeM sync.Mutex
	linksM sync.RWMutex
	links  map[byte]*CAGMuxLink
}

type CAGMuxLink struct {
	mux        *CAGMux
	linkID     byte
	linkUUID   []byte
	traceID    string
	spanID     string
	redqSpanID string

	frames chan cagMuxFrame
	rbuf   []byte

	deadlineM     sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

type cagMuxFrame struct {
	cmd     byte
	payload []byte
	err     error
}

func NewCAGMux(conn net.Conn) *CAGMux {
	m := &CAGMux{
		conn:  conn,
		links: make(map[byte]*CAGMuxLink),
	}
	go m.readLoop()
	return m
}

func OpenCAGMuxLink(ctx context.Context, mux *CAGMux, params *ConnectParams, linkID byte) (*CAGMuxLink, error) {
	return OpenCAGMuxLinkWithTrace(ctx, mux, params, linkID, randomHex(16), randomHex(8))
}

func OpenCAGMuxLinkWithTrace(ctx context.Context, mux *CAGMux, params *ConnectParams, linkID byte, traceID, spanID string) (*CAGMuxLink, error) {
	if mux == nil {
		return nil, fmt.Errorf("missing CAG mux")
	}
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
	link := &CAGMuxLink{
		mux:        mux,
		linkID:     linkID,
		linkUUID:   linkUUID,
		traceID:    traceID,
		spanID:     spanID,
		redqSpanID: randomHex(8),
		frames:     make(chan cagMuxFrame, 64),
	}

	mux.linksM.Lock()
	mux.links[linkID] = link
	mux.linksM.Unlock()

	packet, err := buildCAGProxyAddLinkPacket(params, linkID, linkUUID, traceID, spanID)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = mux.conn.SetWriteDeadline(deadline)
	}
	if _, err := mux.writePacket(packet); err != nil {
		return nil, fmt.Errorf("send CAG proxy add-link: %w", err)
	}
	logger.Debugf("ZTE CAG mux send cmd=0x%02x link=%d len=%d head=%s", cagProxyAddLinkCmd, linkID, len(packet)-4, hexPrefix(packet, 80))
	_ = mux.conn.SetWriteDeadline(time.Time{})
	return link, nil
}

func (m *CAGMux) writePacket(packet []byte) (int, error) {
	m.writeM.Lock()
	defer m.writeM.Unlock()
	return m.conn.Write(packet)
}

func (m *CAGMux) readLoop() {
	for {
		head := make([]byte, 4)
		if _, err := io.ReadFull(m.conn, head); err != nil {
			m.broadcast(cagMuxFrame{err: err})
			return
		}
		cmd := head[0]
		linkID := head[1]
		n := int(binary.LittleEndian.Uint16(head[2:4]))
		payload := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(m.conn, payload); err != nil {
				m.broadcast(cagMuxFrame{err: err})
				return
			}
		}
		logger.Debugf("ZTE CAG mux recv cmd=0x%02x link=%d len=%d", cmd, linkID, n)
		m.linksM.RLock()
		link := m.links[linkID]
		m.linksM.RUnlock()
		if link == nil {
			continue
		}
		err := error(nil)
		if cmd == cagProxyCloseLinkCmd {
			err = io.EOF
		}
		link.frames <- cagMuxFrame{cmd: cmd, payload: payload, err: err}
	}
}

func (m *CAGMux) broadcast(frame cagMuxFrame) {
	m.linksM.RLock()
	defer m.linksM.RUnlock()
	for _, link := range m.links {
		link.frames <- frame
	}
}

func (l *CAGMuxLink) LinkUUID() []byte {
	return append([]byte(nil), l.linkUUID...)
}

func (l *CAGMuxLink) TraceID() string { return l.traceID }

func (l *CAGMuxLink) SpanID() string { return l.spanID }

func (l *CAGMuxLink) REDQSpanID() string { return l.redqSpanID }

func (l *CAGMuxLink) DiscardReadBuffer() {
	l.rbuf = nil
}

func (l *CAGMuxLink) TakeReadBufferN(n int) []byte {
	if n <= 0 || len(l.rbuf) == 0 {
		return nil
	}
	if n > len(l.rbuf) {
		n = len(l.rbuf)
	}
	out := append([]byte(nil), l.rbuf[:n]...)
	l.rbuf = l.rbuf[n:]
	return out
}

func (l *CAGMuxLink) Read(p []byte) (int, error) {
	for len(l.rbuf) == 0 {
		frame, err := l.nextFrame()
		if err != nil {
			return 0, err
		}
		if frame.cmd == cagProxyDataCmd || frame.cmd&0x0f == cagProxyDataCmd {
			l.rbuf = frame.payload
		}
	}
	n := copy(p, l.rbuf)
	l.rbuf = l.rbuf[n:]
	return n, nil
}

func (l *CAGMuxLink) nextFrame() (cagMuxFrame, error) {
	l.deadlineM.Lock()
	deadline := l.readDeadline
	l.deadlineM.Unlock()
	if deadline.IsZero() {
		frame := <-l.frames
		return frame, frame.err
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return cagMuxFrame{}, timeoutError{}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case frame := <-l.frames:
		return frame, frame.err
	case <-timer.C:
		return cagMuxFrame{}, timeoutError{}
	}
}

func (l *CAGMuxLink) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > cagProxyPayloadMax {
			n = cagProxyPayloadMax
		}
		frame := make([]byte, 4+n)
		frame[0] = cagProxyDataCmd
		frame[1] = l.linkID
		binary.LittleEndian.PutUint16(frame[2:4], uint16(n))
		copy(frame[4:], p[:n])
		logger.Debugf("ZTE CAG mux send cmd=0x%02x link=%d len=%d head=%s", cagProxyDataCmd, l.linkID, n, hexPrefix(frame, 80))
		if _, err := l.mux.writePacket(frame); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (l *CAGMuxLink) Close() error {
	l.mux.linksM.Lock()
	delete(l.mux.links, l.linkID)
	l.mux.linksM.Unlock()
	return nil
}

func (l *CAGMuxLink) LocalAddr() net.Addr  { return l.mux.conn.LocalAddr() }
func (l *CAGMuxLink) RemoteAddr() net.Addr { return l.mux.conn.RemoteAddr() }

func (l *CAGMuxLink) SetDeadline(t time.Time) error {
	_ = l.SetReadDeadline(t)
	return l.SetWriteDeadline(t)
}

func (l *CAGMuxLink) SetReadDeadline(t time.Time) error {
	l.deadlineM.Lock()
	l.readDeadline = t
	l.deadlineM.Unlock()
	return nil
}

func (l *CAGMuxLink) SetWriteDeadline(t time.Time) error {
	l.deadlineM.Lock()
	l.writeDeadline = t
	l.deadlineM.Unlock()
	return l.mux.conn.SetWriteDeadline(t)
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
