package soho

import (
	"cloud-computer-keepalive/internal/config"
	"cloud-computer-keepalive/internal/crypto"
	"cloud-computer-keepalive/internal/logger"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func SohoSign(path string, headersList [][2]string, bodyValue string) string {
	var arr []string
	for _, kv := range headersList {
		if kv[1] != "" {
			arr = append(arr, kv[0]+"="+kv[1])
		}
	}
	signStr := "POST&" + path + "&" + strings.Join(arr, "&")
	if bodyValue != "" {
		signStr += "&body=" + bodyValue
	}
	mac := hmac.New(sha256.New, config.SohoSecret)
	mac.Write([]byte(signStr))
	return hex.EncodeToString(mac.Sum(nil))
}

func SohoRequest(path string, bodyData string, sohoToken string, userID string) (map[string]any, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	deviceID := cfg.DeviceID
	appType := config.GetSohoAppType(deviceID)

	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	uuidBytes := make([]byte, 16)
	rand.Read(uuidBytes)
	uuidVal := fmt.Sprintf("uuid_%X", uuidBytes)

	headersList := [][2]string{
		{"X-SOHO-AppKey", config.SohoAppKey},
		{"X-SOHO-AppType", appType},
		{"X-SOHO-ClientVersion", config.SohoClientVer},
		{"X-SOHO-DeviceId", deviceID},
		{"X-SOHO-RomVersion", config.SohoRomVer},
		{"X-SOHO-SohoToken", sohoToken},
		{"X-SOHO-Timestamp", ts},
		{"X-SOHO-UserId", userID},
		{"X-SOHO-Uuid", uuidVal},
		{"X-SOHO-VersionNum", config.SohoVerNum},
	}

	signature := SohoSign(path, headersList, bodyData)

	var bodyStr string
	if bodyData != "" {
		bodyStr = `{"data":"` + bodyData + `"}`
	}

	url := config.SohoBase + path
	req, err := http.NewRequest("POST", url, strings.NewReader(bodyStr))
	if err != nil {
		return nil, err
	}

	for _, kv := range headersList {
		if kv[1] != "" {
			req.Header.Set(kv[0], kv[1])
		}
	}
	req.Header.Set("X-SOHO-Signature", signature)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "jtydn-Mac-"+config.SohoClientVer)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w (body: %s)", err, string(body))
	}
	return result, nil
}

// GetDynamicRSAKey fetches a dynamic RSA public key for password encryption.
func GetDynamicRSAKey() (*rsa.PublicKey, error) {
	bodyJSON := `{"type":1}`
	encrypted, err := crypto.RSAEncryptChunked(bodyJSON)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	result, err := SohoRequest("/login/publicKey/v1", encrypted, "", "")
	if err != nil {
		return nil, err
	}
	code, _ := result["code"].(float64)
	if code != 2000 {
		return nil, fmt.Errorf("%v", result["msg"])
	}
	pubKeyB64, _ := result["data"].(string)
	if pubKeyB64 == "" {
		return nil, fmt.Errorf("empty public key in response")
	}
	return crypto.ParseRSAPublicKey(pubKeyB64)
}

func passwordLogin(path, accountField, account, password string) (map[string]any, error) {
	dynamicKey, err := GetDynamicRSAKey()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	encryptedPwd, err := crypto.RSAEncryptWithKey(password, dynamicKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt password: %w", err)
	}

	loginJSON := fmt.Sprintf(`{"%s":"%s","password":"%s","verificationCode":"","randomCode":""}`, accountField, account, encryptedPwd)
	encryptedBody, err := crypto.RSAEncryptChunked(loginJSON)
	if err != nil {
		return nil, fmt.Errorf("encrypt body: %w", err)
	}

	result, err := SohoRequest(path, encryptedBody, "", "")
	if err != nil {
		return nil, err
	}
	code, _ := result["code"].(float64)
	if code != 2000 {
		return nil, fmt.Errorf("%v", result["msg"])
	}
	data, _ := result["data"].(map[string]any)
	return data, nil
}

// PasswordLogin performs username+password login. Returns the response data map.
func PasswordLogin(username, password string) (map[string]any, error) {
	return passwordLogin("/login/namePwdLogin/v1", "username", username, password)
}

// SubAccountPasswordLogin performs sub-account username+password login.
func SubAccountPasswordLogin(subAccount, password string) (map[string]any, error) {
	return passwordLogin("/login/home/namePwdLogin/v1", "subAccount", subAccount, password)
}

func LoadSohoToken() (string, string) {
	cfg, err := config.LoadConfig()
	if err != nil || cfg.SohoToken == "" {
		logger.Error("Please run login first")
		return "", ""
	}
	return cfg.SohoToken, cfg.UserID
}
