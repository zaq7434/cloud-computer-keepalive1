package cem

import (
	"cloud-computer-keepalive/internal/config"
	"cloud-computer-keepalive/internal/crypto"
	"cloud-computer-keepalive/internal/logger"
	"cloud-computer-keepalive/internal/soho"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ConnectInfo struct {
	ScgIP       string
	ScgPort     string
	ScAuthCode  string
	TraceID     string
	ReadyStatus float64
}

func cemRequest(path string, body any, accessToken string) (map[string]any, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	deviceID := cfg.DeviceID

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	reqURL := config.CEMBase + path
	req, err := http.NewRequest("POST", reqURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("gzs-client-id", config.CEMClientID)
	req.Header.Set("gzs-timestamp", fmt.Sprintf("%d", time.Now().UnixMilli()))
	req.Header.Set("sc-terminal-sn", deviceID)
	req.Header.Set("sc-network-type", "2")
	req.Header.Set("sc-unit-type", "MacBookPro")
	req.Header.Set("User-Agent", fmt.Sprintf("cdpsdk-macos-%s(%s.159)", config.SohoClientVer, config.SohoClientVer))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w (body: %s)", err, string(respBody))
	}
	return result, nil
}

func GetCEMAccessToken(sohoToken, userID string) (string, error) {
	data, err := GetFirmAuth(sohoToken, userID)
	if err != nil {
		return "", err
	}
	scAuthCode, _ := data["scAuthCode"].(string)
	return ExchangeCEMAccessToken(scAuthCode)
}

func GetFirmAuth(sohoToken, userID string) (map[string]any, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.UserServiceID == "" {
		return nil, fmt.Errorf("missing user_service_id in config, please run login first")
	}

	logger.Info("Getting firm auth...")
	bodyJSON := fmt.Sprintf(`{"userServiceId":"%s"}`, cfg.UserServiceID)
	bodyData, err := crypto.RSAEncrypt(bodyJSON)
	if err != nil {
		return nil, fmt.Errorf("rsa encrypt: %w", err)
	}

	result, err := soho.SohoRequest("/cc/getFirmAuth/v1", bodyData, sohoToken, userID)
	if err != nil {
		return nil, fmt.Errorf("getFirmAuth: %w", err)
	}

	code, _ := result["code"].(float64)
	if code != 2000 {
		return nil, fmt.Errorf("getFirmAuth failed: code=%v, msg=%v", result["code"], result["msg"])
	}

	data, _ := result["data"].(map[string]any)
	return data, nil
}

func ExchangeCEMAccessToken(scAuthCode string) (string, error) {
	if scAuthCode == "" {
		return "", fmt.Errorf("empty scAuthCode in firm auth response")
	}

	logger.Info("Getting CEM access_token...")

	// oauth/token
	formData := url.Values{
		"bizCode":    {config.CEMBizCode},
		"client_id":  {config.CEMClientID},
		"grant_type": {"ext"},
		"source":     {"biz"},
		"token":      {scAuthCode},
	}

	req, err := http.NewRequest("POST", config.CEMBase+"/gzs/auth/oauth/token",
		strings.NewReader(formData.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth/token: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var oauthResult map[string]any
	if err := json.Unmarshal(respBody, &oauthResult); err != nil {
		return "", fmt.Errorf("parse oauth response: %w", err)
	}

	oauthCode, _ := oauthResult["code"].(string)
	if oauthCode != "00000" {
		return "", fmt.Errorf("oauth/token failed: code=%v, msg=%v", oauthResult["code"], oauthResult["msg"])
	}

	oauthData, _ := oauthResult["data"].(map[string]any)
	accessToken, _ := oauthData["access_token"].(string)
	logger.Info("CEM access_token obtained")
	return accessToken, nil
}

func GetConnectInfo(accessToken string) (*ConnectInfo, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.VMID == "" {
		return nil, fmt.Errorf("missing vm_id in config, please run login first")
	}

	vmEncrypted, err := crypto.CEMRSAEncrypt(cfg.VMID)
	if err != nil {
		return nil, fmt.Errorf("encrypt vm_id: %w", err)
	}

	result, err := cemRequest("/sc/open-portal/openapi/terminal/v1/getConnectInfo",
		map[string]string{"vmId": vmEncrypted}, accessToken)
	if err != nil {
		return nil, err
	}

	code, _ := result["code"].(string)
	returnCode, _ := result["returnCode"].(string)
	if code != "00000" && returnCode != "00000" {
		msg := result["msg"]
		if msg == nil {
			msg = result["returnMsg"]
		}
		return nil, fmt.Errorf("getConnectInfo failed: code=%v, msg=%v", result["code"], msg)
	}

	data, _ := result["data"].(map[string]any)
	info := &ConnectInfo{
		ScgIP:      getString(data, "scgIp"),
		ScAuthCode: getString(data, "scAuthCode"),
		TraceID:    getString(data, "traceId"),
	}
	info.ScgPort = getString(data, "scgTcpPort")
	if info.ScgPort == "" {
		info.ScgPort = getString(data, "scgPort")
	}
	if info.ScgPort == "" {
		info.ScgPort = "10800"
	}
	if rs, ok := data["readyStatus"].(float64); ok {
		info.ReadyStatus = rs
	}
	return info, nil
}

func WaitVMReady(accessToken, traceID string) (*ConnectInfo, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}

	vmEncrypted, err := crypto.CEMRSAEncrypt(cfg.VMID)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 20; i++ {
		result, err := cemRequest("/sc/open-portal/openapi/terminal/v1/getVmReadyStatus",
			map[string]string{"vmId": vmEncrypted, "traceId": traceID}, accessToken)
		if err != nil {
			logger.Warnf("getVmReadyStatus error: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		data, _ := result["data"].(map[string]any)
		if rs, ok := data["readyStatus"].(float64); ok && rs == 1 {
			info := &ConnectInfo{
				ReadyStatus: 1,
			}
			if sc, ok := data["scAuthCode"].(string); ok {
				info.ScAuthCode = sc
			}
			return info, nil
		}

		logger.Infof("Waiting for VM ready... (%d/20)", i+1)
		time.Sleep(3 * time.Second)
	}
	return nil, fmt.Errorf("VM ready timeout")
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
