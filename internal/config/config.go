package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SOHO platform constants
var SohoSecret, _ = hex.DecodeString("cd58cf413dc43b07993f82f532b0f8e83d259d3ae2305de76811ccd1303853f7")

const (
	SohoAppKey    = "ef80482854c2a2a36311a46011f3303f144bdf69b4b4223cf916f4c7f0f55135"
	SohoClientVer = "2.18.21"
	SohoRomVer    = "Apple Inc.-25.3.0"
	SohoVerNum    = "2182100"
	SohoBase      = "https://soho.komect.com/terminal"
)

const RSAPublicKeyB64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChT7QBLcPBG/WaK7U6jl2H" +
	"nrCx5CObL360yNVGFXjby+nIoJa/LIEibElj2ZwZj7xo7Hph4uTI2V/VVDDH" +
	"ETJSRnQt2gDL5BKHAXL3Wm0A5RAfOfxN9dol8zJuUvkAA9mUx13rNuG4I42/" +
	"K/NXo081YO2chYea2tg8fMqJfCjtwQIDAQAB"

// CEM platform constants
const (
	CEMBase     = "https://api.soho.komect.com:1443"
	CEMClientID = "sc-user-5e38ece5"
	CEMBizCode  = "10002"
)

const CEMRSAPublicKeyB64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRwADvpa+s20CapaSeDeWA" +
	"fRKbK5zD91jIUxNDe/2twuvKdQA+Ln3VWFtL8opVod0ebqQanpVb/uITI56G" +
	"coVdSzis2IgqIkVvN+iOPH+on/FK+6EXYeIZn3MYmVxsmS0IVifVl2EGLeOC" +
	"RMwjPmy9fHB+gByQtGnxAsknwBKUqQIDAQAB"

// AES-128-CTR auth packet encryption
var AuthAESKey = []byte{0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE}

const AuthCTRInit uint64 = 0xFEFEFEFEFEFEFEFE

type Config struct {
	DeviceID      string `json:"device_id,omitempty"`
	Phone         string `json:"phone,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	SubAccount    string `json:"sub_account,omitempty"`
	SubPassword   string `json:"sub_password,omitempty"`
	LoginMode     string `json:"login_mode,omitempty"`
	SohoToken     string `json:"soho_token,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	UserServiceID string `json:"user_service_id,omitempty"`
	VMID          string `json:"vm_id,omitempty"`
}

var configDir string

func init() {
	exe, err := os.Executable()
	if err != nil {
		configDir = "."
	} else {
		configDir = filepath.Dir(exe)
	}
}

func ConfigFilePath() string {
	return filepath.Join(configDir, "cloud_pc.json")
}

func LoadConfig() (*Config, error) {
	data, err := os.ReadFile(ConfigFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func SaveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFilePath(), data, 0644)
}

func GenerateDeviceID() string {
	serial := make([]byte, 5)
	rand.Read(serial)
	serialStr := ""
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for _, b := range serial {
		serialStr += string(chars[int(b)%len(chars)])
	}
	// extend to 10 chars
	serial2 := make([]byte, 5)
	rand.Read(serial2)
	for _, b := range serial2 {
		serialStr += string(chars[int(b)%len(chars)])
	}

	mac := make([]byte, 6)
	rand.Read(mac)
	macStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])

	return serialStr + "-" + macStr
}

func GetSohoAppType(deviceID string) string {
	return fmt.Sprintf("mac|25.3.0|MacBookPro|1|-1|%s|", deviceID)
}
