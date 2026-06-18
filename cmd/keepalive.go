package cmd

import (
	"bytes"
	"cloud-computer-keepalive/internal/cem"
	"cloud-computer-keepalive/internal/chuanyun"
	"cloud-computer-keepalive/internal/config"
	"cloud-computer-keepalive/internal/crypto"
	"cloud-computer-keepalive/internal/logger"
	"cloud-computer-keepalive/internal/scg"
	"cloud-computer-keepalive/internal/soho"
	"cloud-computer-keepalive/internal/spice"
	"cloud-computer-keepalive/internal/zte"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func Keepalive(args []string) {
	duration := 120
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--duration":
			if i+1 < len(args) {
				d, err := strconv.Atoi(args[i+1])
				if err == nil {
					duration = d
				}
				i++
			}
		case "--forever":
			duration = 0
		}
	}

	sohoToken, userID := soho.LoadSohoToken()
	if sohoToken == "" {
		os.Exit(1)
	}
	logger.Infof("SohoToken: %s", logger.Mask(sohoToken, 4))

	// 1. Get firm auth. Sub-account/ZTE clients may receive CAG/VMC fields
	// without an SCG auth code, matching the official Windows client flow.
	firmAuth, err := cem.GetFirmAuth(sohoToken, userID)
	if err != nil {
		logger.Errorf("getFirmAuth failed: %v", err)
		os.Exit(1)
	}
	firmAuthCode, _ := firmAuth["scAuthCode"].(string)
	if firmAuthCode == "" {
		if err := keepaliveZTE(firmAuth, sohoToken, userID, duration); err != nil {
			logger.Errorf("ZTE keepalive failed: %v", err)
			os.Exit(1)
		}
		return
	}

	accessToken, err := cem.ExchangeCEMAccessToken(firmAuthCode)
	if err != nil {
		logger.Errorf("Get CEM access_token failed: %v", err)
		os.Exit(1)
	}

	// 2. Call getConnectInfo to trigger VM boot
	logger.Info("Calling getConnectInfo...")
	connectInfo, err := cem.GetConnectInfo(accessToken)
	if err != nil {
		logger.Errorf("getConnectInfo failed: %v", err)
		os.Exit(1)
	}

	logger.Infof("SCG: %s:%s, readyStatus=%.0f", connectInfo.ScgIP, connectInfo.ScgPort, connectInfo.ReadyStatus)
	logger.Infof("scAuthCode: %d chars", len(connectInfo.ScAuthCode))

	scAuthCode := connectInfo.ScAuthCode

	// 3. Wait for VM ready
	if connectInfo.ReadyStatus != 1 && connectInfo.TraceID != "" {
		logger.Info("Waiting for VM ready...")
		readyInfo, err := cem.WaitVMReady(accessToken, connectInfo.TraceID)
		if err != nil {
			logger.Errorf("VM ready timeout: %v", err)
			os.Exit(1)
		}
		if readyInfo.ScAuthCode != "" {
			scAuthCode = readyInfo.ScAuthCode
			logger.Infof("Using getVmReadyStatus scAuthCode (%d chars)", len(scAuthCode))
		}
		logger.Info("VM ready")
	}

	// 4. Connect SCG and authenticate
	cfg, _ := config.LoadConfig()
	tlsConn, _, err := scg.ConnectSCG(connectInfo.ScgIP, connectInfo.ScgPort, scAuthCode, cfg.VMID)
	if err != nil {
		logger.Errorf("Connect SCG failed: %v", err)
		os.Exit(1)
	}

	// 5. Keepalive loop
	keepaliveLoop(tlsConn, sohoToken, userID, duration)
}

func keepaliveZTE(firmAuth map[string]any, sohoToken, userID string, duration int) error {
	return keepaliveZTESession(firmAuth, sohoToken, userID, duration)
}

func keepaliveZTESession(firmAuth map[string]any, sohoToken, userID string, duration int) error {
	logFirmAuthFallback(firmAuth)

	firm := zte.FirmAuth{
		VMUserName: jsonString(firmAuth["vmUserName"]),
		VMPassword: jsonString(firmAuth["vmPassword"]),
		VMID:       jsonString(firmAuth["vmId"]),
		VMCIP:      jsonString(firmAuth["vmcIp"]),
		VMCPort:    mustAtoi(jsonString(firmAuth["vmcPort"])),
		CAGIP:      jsonString(firmAuth["cagIp"]),
		CAGPort:    mustAtoi(jsonString(firmAuth["cagPort"])),
	}
	if firm.VMUserName == "" || firm.VMPassword == "" || firm.VMID == "" || firm.CAGIP == "" || firm.CAGPort == 0 {
		return fmt.Errorf("firm auth is missing required ZTE fields")
	}

	client := zte.NewClient(firm)
	logger.Info("ZTE sysConfig...")
	if _, err := client.SysConfig(); err != nil {
		logger.Warnf("ZTE sysConfig failed, continue: %v", err)
	}

	logger.Info("ZTE getToken...")
	token, err := client.GetAccessToken()
	if err != nil {
		return err
	}
	logger.Infof("ZTE accessToken: %s", logger.Mask(token.AccessToken, 4))

	logger.Info("ZTE getDesktopList...")
	list, err := client.GetDesktopList(token.AccessToken)
	if err != nil {
		return err
	}
	desktop := zte.FirstDesktop(list, firm.VMID)
	if desktop == nil {
		return fmt.Errorf("ZTE desktop list has no matching vmId")
	}

	logger.Info("ZTE startDesktop...")
	start, err := client.StartDesktop(token.AccessToken, desktop)
	if err != nil {
		return err
	}
	connectStr := jsonString(start["connectStr"])
	if connectStr == "" {
		logger.Info("ZTE startDesktop returned no connectStr, querying async result...")
		for i := 0; i < 30; i++ {
			async, err := client.StartDesktopAsyncQuery(token.AccessToken)
			if err != nil {
				return err
			}
			connectStr = jsonString(async["connectStr"])
			if connectStr != "" {
				logger.Infof("ZTE async start ready after %ds", (i+1)*2)
				break
			}
			time.Sleep(2 * time.Second)
		}
	}
	if connectStr == "" {
		return fmt.Errorf("ZTE startDesktop did not return connectStr")
	}

	params, err := zte.DecodeConnectParams(connectStr)
	if err != nil {
		return err
	}
	logger.Infof("ZTE target: spice=%s:%d vmId=%s proxySport=%d", params.Host, params.Port, logger.Mask(params.VMID, 4), params.ProxySport)

	authTemplate := os.Getenv("CCK_ZTE_CAG_AUTH_TEMPLATE_HEX")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cagAddr := fmt.Sprintf("%s:%d", firm.CAGIP, firm.CAGPort)
	logger.Infof("Connecting ZTE CAG %s...", cagAddr)
	tlsConn, session, err := zte.DialCAGTCPTLS(ctx, zte.CAGDialOptions{
		Address:         cagAddr,
		Params:          params,
		AuthTemplateHex: authTemplate,
		Timeout:         30 * time.Second,
	})
	if err != nil {
		logger.Warnf("ZTE CAG TCP/TLS failed, trying UDP/KCP path: %v", err)
		tlsConn, session, err = zte.DialCAGTLS(ctx, zte.CAGDialOptions{
			Address:         cagAddr,
			Params:          params,
			AuthTemplateHex: authTemplate,
			Timeout:         30 * time.Second,
		})
		if err != nil {
			return err
		}
	}
	defer tlsConn.Close()
	logger.Infof("ZTE CAG TLS established: conv=0x%08x", session.Conv)

	mux := zte.NewCAGMux(tlsConn)
	proxyConn, err := zte.OpenCAGMuxLink(ctx, mux, params, 1)
	if err != nil {
		return err
	}
	logger.Info("ZTE CAG proxy add-link sent")
	rawResult := spice.RawMainHandshake(proxyConn, params.Key, params.VMID, proxyConn.LinkUUID(), proxyConn.TraceID(), proxyConn.REDQSpanID())
	if !rawResult.OK {
		return fmt.Errorf("ZTE raw SPICE main handshake failed")
	}
	subLinks, authed, err := sendZTESubchannelREDQs(ctx, mux, params, proxyConn, rawResult.SpiceSessionID)
	if err != nil {
		logger.Warnf("ZTE subchannel REDQ probe failed: %v", err)
	}
	startZTESubchannelKeepalive(subLinks, authed)
	return keepaliveRawSpiceLoop(proxyConn, sohoToken, userID, duration)
}

func sendZTESubchannelREDQs(ctx context.Context, mux *zte.CAGMux, params *zte.ConnectParams, main *zte.CAGMuxLink, connectionID uint32) (map[byte]*zte.CAGMuxLink, map[byte]bool, error) {
	type subREDQ struct {
		linkID      byte
		channelType uint8
		channelID   uint8
	}
	firstLinks := []byte{2, 3, 4, 5}
	secondLinks := []byte{6, 7, 8}
	redqs := []subREDQ{
		{linkID: 3, channelType: 4, channelID: 1},
		{linkID: 2, channelType: 6, channelID: 0},
		{linkID: 4, channelType: 5, channelID: 0},
		{linkID: 6, channelType: 3, channelID: 0},
		{linkID: 7, channelType: 2, channelID: 0},
		{linkID: 8, channelType: 4, channelID: 0},
		{linkID: 5, channelType: 2, channelID: 1},
	}

	links := make(map[byte]*zte.CAGMuxLink)
	for _, linkID := range firstLinks {
		link, err := zte.OpenCAGMuxLinkWithTrace(ctx, mux, params, linkID, main.TraceID(), main.SpanID())
		if err != nil {
			return links, nil, err
		}
		links[linkID] = link
	}
	for _, item := range redqs[:3] {
		payload := spice.BuildZTERawChannelREDQ(params.Key, params.VMID, main.LinkUUID(), main.TraceID(), main.REDQSpanID(), connectionID, item.channelType, item.channelID)
		if _, err := links[item.linkID].Write(payload); err != nil {
			return links, nil, err
		}
	}
	for _, linkID := range secondLinks {
		link, err := zte.OpenCAGMuxLinkWithTrace(ctx, mux, params, linkID, main.TraceID(), main.SpanID())
		if err != nil {
			return links, nil, err
		}
		links[linkID] = link
	}
	for _, item := range redqs[3:] {
		payload := spice.BuildZTERawChannelREDQ(params.Key, params.VMID, main.LinkUUID(), main.TraceID(), main.REDQSpanID(), connectionID, item.channelType, item.channelID)
		if _, err := links[item.linkID].Write(payload); err != nil {
			return links, nil, err
		}
	}
	logger.Infof("ZTE subchannel REDQ probe sent (connectionID=0x%s)", logger.Mask(fmt.Sprintf("%08x", connectionID), 4))
	authed := authenticateZTESubchannels(links, 8*time.Second)
	return links, authed, nil
}

func authenticateZTESubchannels(links map[byte]*zte.CAGMuxLink, timeout time.Duration) map[byte]bool {
	pending := make(map[byte][]byte)
	authing := make(map[byte]bool)
	done := make(map[byte]bool)
	deadline := time.Now().Add(timeout)
	defer func() {
		logger.Infof("ZTE subchannel auth completed: %d/%d", len(done), len(links))
	}()
	defer func() {
		for linkID, link := range links {
			if done[linkID] {
				_ = link.SetReadDeadline(time.Time{})
			}
		}
	}()
	for time.Now().Before(deadline) && len(done) < len(links) {
		progress := false
		for linkID, link := range links {
			if done[linkID] {
				continue
			}
			_ = link.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			payload := make([]byte, 4096)
			n, err := link.Read(payload)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				logger.Debugf("ZTE subchannel link=%d read stopped: %v", linkID, err)
				continue
			}
			payload = payload[:n]
			progress = true
			if authing[linkID] && len(payload) == 4 {
				result := binary.LittleEndian.Uint32(payload)
				logger.Debugf("ZTE subchannel link=%d auth result=%d", linkID, result)
				if result == 0 {
					done[linkID] = true
				}
				continue
			}
			pending[linkID] = append(pending[linkID], payload...)
			if !authing[linkID] && len(pending[linkID]) > 32 {
				if !bytes.Contains(pending[linkID], []byte("REDQ")) {
					continue
				}
				ticket := make([]byte, 128)
				if _, err := link.Write(ticket); err != nil {
					return done
				}
				authing[linkID] = true
				logger.Debugf("ZTE subchannel link=%d auth ticket sent", linkID)
			}
		}
		if !progress {
			time.Sleep(20 * time.Millisecond)
		}
	}
	return done
}

func startZTESubchannelKeepalive(links map[byte]*zte.CAGMuxLink, authed map[byte]bool) {
	for linkID, link := range links {
		if !authed[linkID] {
			continue
		}
		switch linkID {
		case 6:
			if _, err := spice.WriteRawMessage(link, 1, spice.BuildZTERawInputInit()); err != nil {
				logger.Warnf("ZTE input init failed on link=%d: %v", linkID, err)
			} else {
				logger.Debugf("ZTE input init sent on link=%d", linkID)
			}
		case 5, 7:
			if _, err := spice.WriteRawMessage(link, 1, spice.BuildZTERawDisplayInit()); err != nil {
				logger.Warnf("ZTE display init failed on link=%d: %v", linkID, err)
			} else {
				logger.Debugf("ZTE display init sent on link=%d", linkID)
			}
		}
		go keepZTESubchannelAlive(linkID, link)
	}
}

func keepZTESubchannelAlive(linkID byte, link *zte.CAGMuxLink) {
	state := &spice.RawState{}
	for {
		msgType, payload, err := state.ReadMessage(link, 30*time.Second)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if err != io.EOF {
				logger.Debugf("ZTE subchannel link=%d stopped: %v", linkID, err)
			}
			return
		}
		logger.Debugf("ZTE subchannel link=%d recv msg=0x%02x len=%d", linkID, msgType, len(payload))
		if state.AutoReply(link, msgType, payload) {
			logger.Debugf("ZTE subchannel link=%d auto-reply msg=0x%02x", linkID, msgType)
		}
	}
}

func keepaliveRawSpiceLoop(conn net.Conn, sohoToken, userID string, duration int) error {
	if duration > 0 {
		logger.Infof("Keeping raw SPICE connection for %ds...", duration)
	} else {
		logger.Info("Persistent raw SPICE keepalive (Ctrl+C to exit)...")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	start := time.Now()
	heartbeatCount := 0
	rawState := &spice.RawState{}
	nextHeartbeat := start

	defer func() {
		conn.Close()
		logger.Info("Raw SPICE connection closed")
	}()

	for {
		select {
		case <-sigCh:
			logger.Info("User interrupted")
			return nil
		default:
		}

		elapsed := int(time.Since(start).Seconds())
		if duration > 0 && elapsed >= duration {
			logger.Infof("Raw SPICE keepalive %ds done, disconnecting", elapsed)
			return nil
		}

		now := time.Now()
		if !now.Before(nextHeartbeat) {
			cfg, _ := config.LoadConfig()
			if cfg.UserServiceID != "" {
				bodyJSON := fmt.Sprintf(`{"userServiceId":"%s"}`, cfg.UserServiceID)
				bodyData, err := crypto.RSAEncrypt(bodyJSON)
				if err == nil {
					if _, err = soho.SohoRequest("/cc/cloudPc/heartbeat/v2", bodyData, sohoToken, userID); err != nil {
						logger.Warnf("Heartbeat error: %v", err)
					}
				}
			}
			heartbeatCount++
			logger.Infof("Raw SPICE heartbeat #%d (uptime=%ds)", heartbeatCount, elapsed)
			nextHeartbeat = now.Add(25 * time.Second)
		}

		msgType, payload, err := rawState.ReadMessage(conn, 1*time.Second)
		if err != nil {
			if err == io.EOF {
				logger.Info("Raw SPICE server closed connection")
				return fmt.Errorf("raw SPICE server closed connection")
			}
			continue
		}
		logger.Debugf("Raw SPICE loop recv msg=0x%02x len=%d", msgType, len(payload))
		if rawState.AutoReply(conn, msgType, payload) {
			logger.Debugf("Raw SPICE auto-reply msg=0x%02x", msgType)
		}
	}
}

func keepaliveLoop(conn net.Conn, sohoToken, userID string, duration int) {
	if duration > 0 {
		logger.Infof("Keeping connection for %ds...", duration)
	} else {
		logger.Info("Persistent keepalive (Ctrl+C to exit)...")
	}

	// SPICE handshake
	result := spice.SpiceHandshake(conn)
	logger.Infof("Handshake result: spice=%v channels=%v", result.SpiceOK, result.ConnectedChannels)
	logger.Debugf("sid=0x%x spice_sid=0x%x", result.SessionID, result.SpiceSessionID)

	sid := result.SessionID

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	start := time.Now()
	heartbeatCount := 0

	defer func() {
		conn.Close()
		logger.Info("Connection closed")
	}()

	for {
		select {
		case <-sigCh:
			logger.Info("User interrupted")
			return
		default:
		}

		elapsed := int(time.Since(start).Seconds())
		if duration > 0 && elapsed >= duration {
			logger.Infof("Keepalive %ds done, disconnecting", elapsed)
			return
		}

		// SOHO API heartbeat
		cfg, _ := config.LoadConfig()
		if cfg.UserServiceID != "" {
			bodyJSON := fmt.Sprintf(`{"userServiceId":"%s"}`, cfg.UserServiceID)
			bodyData, err := crypto.RSAEncrypt(bodyJSON)
			if err == nil {
				_, err = soho.SohoRequest("/cc/cloudPc/heartbeat/v2", bodyData, sohoToken, userID)
				if err != nil {
					logger.Warnf("Heartbeat error: %v", err)
				}
			}
		}
		heartbeatCount++

		// Send MOUSE_MODE_REQUEST on main channel
		if result.SpiceOK {
			mouseMode := make([]byte, 10)
			binary.LittleEndian.PutUint16(mouseMode[0:2], 0x69)
			binary.LittleEndian.PutUint32(mouseMode[2:6], 4)
			binary.LittleEndian.PutUint32(mouseMode[6:10], 2)
			head := chuanyun.FrameHeadPack(spice.DataType, uint16(len(mouseMode)), sid, 1)
			conn.Write(append(head, mouseMode...))
		}

		logger.Infof("Heartbeat #%d (uptime=%ds, spice=%v, channels=%v)",
			heartbeatCount, elapsed, result.SpiceOK, result.ConnectedChannels)

		// Consume and parse server data
		frames := chuanyun.RecvAllFrames(conn, 1*time.Second, 10)
		for _, frame := range frames {
			if frame.PktType == chuanyun.TrunkSwitch && len(frame.Payload) >= 32 {
				targetCID := binary.LittleEndian.Uint64(frame.Payload[0:8])
				_ = targetCID
				senderCID := binary.LittleEndian.Uint64(frame.Payload[8:16])
				param := binary.LittleEndian.Uint32(frame.Payload[16:20])
				switchReason := frame.Payload[20]
				extraID := binary.LittleEndian.Uint64(frame.Payload[24:32])
				resp := chuanyun.TrunkSwitchPack(senderCID, sid, param, switchReason, extraID, frame.Field1, frame.Field2)
				conn.Write(resp)
				logger.Debugf("Switch reply: reason=%d", switchReason)
				continue
			}

			if frame.PktType == spice.DataType && len(frame.Payload) >= 6 {
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
					head := chuanyun.FrameHeadPack(spice.DataType, uint16(len(pong)), sid, frame.Field2)
					conn.Write(append(head, pong...))
					logger.Debugf("PING -> PONG (ch=%s)", chName)
				} else if msgType == 0x03 { // SET_ACK -> ACK_SYNC
					var generation uint32
					if len(frame.Payload) >= 10 {
						generation = binary.LittleEndian.Uint32(frame.Payload[6:10])
					}
					ackSync := make([]byte, 10)
					binary.LittleEndian.PutUint16(ackSync[0:2], 0x01)
					binary.LittleEndian.PutUint32(ackSync[2:6], 4)
					binary.LittleEndian.PutUint32(ackSync[6:10], generation)
					head := chuanyun.FrameHeadPack(spice.DataType, uint16(len(ackSync)), sid, frame.Field2)
					conn.Write(append(head, ackSync...))
					logger.Debugf("SET_ACK -> ACK_SYNC (gen=%d, ch=%s)", generation, chName)
				}
			}
		}

		// Connection probe
		if len(frames) == 0 {
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			probe := make([]byte, 1)
			_, err := conn.Read(probe)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// timeout is ok
				} else {
					logger.Error("SCG connection lost")
					return
				}
			}
			conn.SetReadDeadline(time.Time{})
		}

		time.Sleep(25 * time.Second)
	}
}

func sendSohoCloudPCAction(path, sohoToken, userID string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if cfg.UserServiceID == "" {
		return fmt.Errorf("missing user_service_id in config, please run login first")
	}

	bodyJSON := fmt.Sprintf(`{"userServiceId":"%s"}`, cfg.UserServiceID)
	bodyData, err := crypto.RSAEncrypt(bodyJSON)
	if err != nil {
		return err
	}

	result, err := soho.SohoRequest(path, bodyData, sohoToken, userID)
	if err != nil {
		return err
	}
	code, _ := result["code"].(float64)
	if code != 2000 && code != 4041 {
		return fmt.Errorf("code=%v, msg=%v", result["code"], result["msg"])
	}
	return nil
}

func logFirmAuthFallback(data map[string]any) {
	vmc := jsonString(data["vmcIp"])
	vmcPort := jsonString(data["vmcPort"])
	cag := jsonString(data["cagIp"])
	cagPort := jsonString(data["cagPort"])
	vmID := jsonString(data["vmId"])
	if vmc != "" || cag != "" {
		logger.Infof("Firm auth: vmId=%s, vmc=%s:%s, cag=%s:%s",
			logger.Mask(vmID, 4), vmc, vmcPort, cag, cagPort)
	}
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
