package cmd

import (
	"cloud-computer-keepalive/internal/cem"
	"cloud-computer-keepalive/internal/chuanyun"
	"cloud-computer-keepalive/internal/config"
	"cloud-computer-keepalive/internal/crypto"
	"cloud-computer-keepalive/internal/logger"
	"cloud-computer-keepalive/internal/scg"
	"cloud-computer-keepalive/internal/soho"
	"cloud-computer-keepalive/internal/spice"
	"encoding/binary"
	"encoding/json"
	"fmt"
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
		logFirmAuthFallback(firmAuth)
		logger.Error("Firm auth has no scAuthCode; this account uses the ZTE CAG/VMC client path, which is not supported by the SCG keepalive implementation")
		os.Exit(1)
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

// suppress unused import warning
var _ = json.Marshal
