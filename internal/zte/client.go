package zte

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	ClientVersion = "V7.24.11"
	requestFrom   = "2"
	defaultMac    = "8C-04-BA-9C-C2-E7"
	defaultIP     = "192.168.1.165"
	defaultHost   = "wangpeng-pc"
	defaultUStr   = "31BF5444-86E0-4D5D-B1AB-A42FFBAC72C9"
)

type FirmAuth struct {
	VMUserName string
	VMPassword string
	VMID       string
	VMCIP      string
	VMCPort    int
	CAGIP      string
	CAGPort    int
}

type Client struct {
	FirmAuth     FirmAuth
	HTTP         *http.Client
	TerminalUUID string
	SerialNumber string
}

type TokenInfo struct {
	AccessToken string
	Raw         map[string]any
}

type queryParam struct {
	Key   string
	Value string
}

func NewClient(firm FirmAuth) *Client {
	terminalUUID := newUUID()
	serialNumber := newUUID()
	jar, _ := cookiejar.New(nil)
	return &Client{
		FirmAuth:     firm,
		TerminalUUID: terminalUUID,
		SerialNumber: serialNumber,
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // ZTE CAG uses the bundled client trust store.
				TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
			},
		},
	}
}

func (c *Client) SysConfig() (map[string]any, error) {
	values := []queryParam{
		{"version", ClientVersion},
		{"language", "zh"},
		{"requestFrom", requestFrom},
		{"name", c.FirmAuth.VMUserName},
		{"RspSecurity", "1"},
	}
	return c.request("/cs/cs_sysConfig.action", values, "")
}

func (c *Client) GetAccessToken() (*TokenInfo, error) {
	f := c.FirmAuth
	password, err := EncodeVDIPassword(f.VMPassword)
	if err != nil {
		return nil, err
	}
	values := []queryParam{
		{"username", f.VMUserName},
		{"password", password},
		{"version", ClientVersion},
		{"language", "zh"},
		{"clientId", ""},
		{"encrypt", "4"},
		{"token", ""},
		{"requestFrom", requestFrom},
		{"mac", defaultMac},
		{"clientIp", defaultIP},
		{"hostName", defaultHost},
		{"newVersionCtrl", "1"},
		{"netflags", "1"},
		{"unityType", "1"},
		{"isvm", "0"},
		{"RspSecurity", "1"},
	}
	body := map[string]int{
		"clienttype": 0,
		"hardware":   4,
		"nettype":    2,
		"ostype":     1,
	}
	result, err := c.request("/cs/cs_getToken.action", values, body)
	if err != nil {
		return nil, err
	}
	token, _ := result["accessToken"].(string)
	if token == "" {
		return nil, fmt.Errorf("missing accessToken in response: %v", result)
	}
	return &TokenInfo{AccessToken: token, Raw: result}, nil
}

func (c *Client) GetDesktopList(accessToken string) (map[string]any, error) {
	values := []queryParam{
		{"accessToken", accessToken},
		{"type", "7"},
		{"version", ClientVersion},
		{"language", "zh"},
		{"clientIp", defaultIP},
		{"requestFrom", requestFrom},
		{"isvm", "0"},
		{"RspSecurity", "1"},
	}
	return c.request("/cs/cs_getDesktopList.action", values, "")
}

func (c *Client) StartDesktop(accessToken string, desktop map[string]any) (map[string]any, error) {
	body := c.startDesktopBody(accessToken, desktop)
	return c.request("/cs/cs_startDesktop.action", nil, body)
}

func (c *Client) StartDesktopAsyncQuery(accessToken string) (map[string]any, error) {
	values := []queryParam{
		{"accessToken", accessToken},
		{"language", "zh"},
		{"isvm", "0"},
		{"vmid", c.FirmAuth.VMID},
		{"RspSecurity", "1"},
		{"prover", "1"},
		{"allowSwitchRap", "1"},
	}
	return c.request("/cs/cs_startDesktop_async_query.action", values, "")
}

func (c *Client) request(path string, values []queryParam, body any) (map[string]any, error) {
	if c.HTTP == nil {
		c.HTTP = NewClient(c.FirmAuth).HTTP
	}
	query := encodeQuery(values)
	reqURL := fmt.Sprintf("https://%s:%d%s", c.FirmAuth.CAGIP, c.FirmAuth.CAGPort, path)
	if query != "" {
		reqURL += "?" + query
	}

	encryptedBody, err := encodeRequestBody(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", reqURL, bytes.NewBufferString(encryptedBody))
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("zte %s failed: status=%d body=%s", path, resp.StatusCode, string(respBody))
	}
	result, err := DecodeSecurityJSON(respBody)
	if err != nil {
		return nil, fmt.Errorf("zte %s: %w", path, err)
	}
	if ok, _ := result["success"].(bool); !ok {
		return nil, fmt.Errorf("zte %s failed: %s", path, compactJSON(result))
	}
	return result, nil
}

func encodeQuery(values []queryParam) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, item := range values {
		value := url.QueryEscape(item.Value)
		if item.Key == "hostName" {
			value = strings.ReplaceAll(value, "-", "%2D")
		}
		parts = append(parts, url.QueryEscape(item.Key)+"="+value)
	}
	return strings.Join(parts, "&")
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "*/*")
}

func (c *Client) startDesktopBody(accessToken string, desktop map[string]any) map[string]any {
	userID := intValue(desktop["userId"])
	groupID := intValue(desktop["groupId"])
	poolID := intValue(desktop["poolId"])
	assignRelation := fmt.Sprintf("%d,%d,%d", userID, groupID, poolID)
	if userID == 0 && groupID == 0 && poolID == 0 {
		assignRelation = ""
	}

	return map[string]any{
		"RspSecurity":            1,
		"SNcode":                 c.serialNumber(),
		"accessToken":            accessToken,
		"allowExtUSBPolicy":      1,
		"allowSwitchRap":         1,
		"assignRelationtoString": assignRelation,
		"connectionType":         intValueDefault(desktop["connectionType"], 0),
		"diskNo":                 "2250008001546",
		"encryption":             1,
		"hostName":               defaultHost,
		"isvm":                   0,
		"language":               "zh",
		"localipandmac":          defaultIP + "," + defaultMac,
		"netType":                2,
		"newcharsetparse":        1,
		"newpara":                1,
		"prover":                 1,
		"raptype":                2,
		"requestFrom":            intValueDefault(requestFrom, 2),
		"supportAsync":           1,
		"supportCustomConfig":    "00000000000000000000000000000011",
		"type":                   intValueDefault(desktop["desktopType"], 1),
		"upmnew":                 1,
		"uuid":                   stringValue(desktop["uuid"]),
		"verifyTerminalBind":     "11",
		"version":                ClientVersion,
		"vmid":                   c.FirmAuth.VMID,
		"watermarkType":          1,
	}
}

func encodeRequestBody(body any) (string, error) {
	switch v := body.(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("marshal zte request body: %w", err)
		}
		return string(data), nil
	}
}

func FirstDesktop(list map[string]any, vmID string) map[string]any {
	desktops, _ := list["desktopList"].([]any)
	for _, item := range desktops {
		desktop, _ := item.(map[string]any)
		if desktop == nil {
			continue
		}
		if vmID == "" || stringValue(desktop["vmId"]) == vmID {
			return desktop
		}
	}
	return nil
}

func (c *Client) serialNumber() string {
	if c.SerialNumber != "" {
		return c.SerialNumber
	}
	return defaultUStr
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return defaultUStr
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func stringValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func intValue(v any) int {
	return intValueDefault(v, 0)
}

func intValueDefault(v any, def int) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, err := strconv.Atoi(x)
		if err == nil {
			return n
		}
	}
	return def
}

func compactJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSpace(string(data))
}
