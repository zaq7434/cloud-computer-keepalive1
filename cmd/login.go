package cmd

import (
	"bufio"
	"cloud-computer-keepalive/internal/config"
	"cloud-computer-keepalive/internal/crypto"
	"cloud-computer-keepalive/internal/logger"
	"cloud-computer-keepalive/internal/soho"
	"fmt"
	"os"
	"strings"
)

func Login() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("[?] 已阅读以上声明，理解使用该程序造成的问题与作者无关 [y/N]: ")
	scanner.Scan()
	if strings.ToLower(strings.TrimSpace(scanner.Text())) != "y" {
		fmt.Println("[-] 未确认，退出")
		os.Exit(0)
	}
	fmt.Println()

	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("[-] Load config error: %v\n", err)
		os.Exit(1)
	}

	// 1. Device ID
	if cfg.DeviceID != "" {
		fmt.Printf("[*] Device ID: %s\n", cfg.DeviceID)
	} else {
		cfg.DeviceID = config.GenerateDeviceID()
		config.SaveConfig(cfg)
		fmt.Printf("[+] Generated device ID: %s\n", cfg.DeviceID)
	}

	// 2. Choose login method
	fmt.Println()
	fmt.Println("[*] Login method:")
	fmt.Println("    [1] SMS code")
	fmt.Println("    [2] Account password")
	defaultMethod := "1"
	if cfg.Username != "" {
		defaultMethod = "2"
	}
	fmt.Printf("[?] Choose [%s]: ", defaultMethod)
	scanner.Scan()
	method := strings.TrimSpace(scanner.Text())
	if method == "" {
		method = defaultMethod
	}

	var data map[string]any
	switch method {
	case "1":
		data = loginSMS(scanner, cfg)
	case "2":
		data = loginPassword(scanner, cfg)
	default:
		fmt.Printf("[-] Invalid choice: %s\n", method)
		os.Exit(1)
	}

	cfg.SohoToken, _ = data["sohoToken"].(string)
	userIDFloat, _ := data["userId"].(float64)
	cfg.UserID = fmt.Sprintf("%.0f", userIDFloat)
	fmt.Printf("[+] Login success! UserId: %s\n", logger.Mask(cfg.UserID, 4))

	// 3. Get cloud PC info
	fetchCloudPC(scanner, cfg)
	config.SaveConfig(cfg)

	fmt.Printf("[+] vmId: %s\n", cfg.VMID)
	fmt.Printf("[+] Config saved to %s\n", config.ConfigFilePath())
	fmt.Println()
	fmt.Println("Now you can run:")
	fmt.Println("  ./cloudpc keepalive --duration 60")
}

func loginSMS(scanner *bufio.Scanner, cfg *config.Config) map[string]any {
	// Phone number
	phone := cfg.Phone
	if phone != "" {
		fmt.Printf("[?] Phone [%s]: ", logger.MaskPhone(phone))
		scanner.Scan()
		inp := strings.TrimSpace(scanner.Text())
		if inp != "" {
			phone = inp
		}
	} else {
		fmt.Print("[?] Phone: ")
		scanner.Scan()
		phone = strings.TrimSpace(scanner.Text())
	}
	if phone == "" {
		fmt.Println("[-] Phone cannot be empty")
		os.Exit(1)
	}
	cfg.Phone = phone
	config.SaveConfig(cfg)

	// Send SMS code
	fmt.Printf("[*] Sending SMS code to %s...\n", logger.MaskPhone(phone))
	smsJSON := fmt.Sprintf(`{"phone":"%s"}`, phone)
	encrypted, err := crypto.RSAEncrypt(smsJSON)
	if err != nil {
		fmt.Printf("[-] Encrypt error: %v\n", err)
		os.Exit(1)
	}

	result, err := soho.SohoRequest("/login/sms/send/v1", encrypted, "", "")
	if err != nil {
		fmt.Printf("[-] Send SMS error: %v\n", err)
		os.Exit(1)
	}
	code, _ := result["code"].(float64)
	if code != 2000 {
		fmt.Printf("[-] Send failed: %v\n", result["msg"])
		os.Exit(1)
	}
	fmt.Println("[+] SMS code sent")

	// Input SMS code and login
	fmt.Print("[?] SMS code: ")
	scanner.Scan()
	smsCode := strings.TrimSpace(scanner.Text())
	if smsCode == "" {
		fmt.Println("[-] SMS code cannot be empty")
		os.Exit(1)
	}

	loginJSON := fmt.Sprintf(`{"smsCode":"%s","phone":"%s"}`, smsCode, phone)
	encrypted, err = crypto.RSAEncrypt(loginJSON)
	if err != nil {
		fmt.Printf("[-] Encrypt error: %v\n", err)
		os.Exit(1)
	}

	result, err = soho.SohoRequest("/login/sms/login/v1", encrypted, "", "")
	if err != nil {
		fmt.Printf("[-] Login error: %v\n", err)
		os.Exit(1)
	}
	code, _ = result["code"].(float64)
	if code != 2000 {
		fmt.Printf("[-] Login failed: %v\n", result["msg"])
		os.Exit(1)
	}

	data, _ := result["data"].(map[string]any)
	return data
}

func loginPassword(scanner *bufio.Scanner, cfg *config.Config) map[string]any {
	// Username
	username := cfg.Username
	if username != "" {
		fmt.Printf("[?] Username [%s]: ", logger.Mask(username, 4))
		scanner.Scan()
		inp := strings.TrimSpace(scanner.Text())
		if inp != "" {
			username = inp
		}
	} else {
		fmt.Print("[?] Username: ")
		scanner.Scan()
		username = strings.TrimSpace(scanner.Text())
	}
	if username == "" {
		fmt.Println("[-] Username cannot be empty")
		os.Exit(1)
	}

	// Password
	password := cfg.Password
	if password != "" {
		fmt.Print("[?] Password [****]: ")
		scanner.Scan()
		inp := strings.TrimSpace(scanner.Text())
		if inp != "" {
			password = inp
		}
	} else {
		fmt.Print("[?] Password: ")
		scanner.Scan()
		password = strings.TrimSpace(scanner.Text())
	}
	if password == "" {
		fmt.Println("[-] Password cannot be empty")
		os.Exit(1)
	}

	fmt.Printf("[*] Logging in as %s...\n", logger.Mask(username, 4))
	data, err := soho.PasswordLogin(username, password)
	if err != nil {
		fmt.Printf("[-] Login failed: %v\n", err)
		os.Exit(1)
	}

	// Save credentials for future login
	cfg.Username = username
	cfg.Password = password
	if phone, _ := data["phone"].(string); phone != "" {
		cfg.Phone = phone
	}

	return data
}

func fetchCloudPC(scanner *bufio.Scanner, cfg *config.Config) {
	fmt.Println("[*] Getting cloud PC list...")
	listJSON := `{"pageNum":1,"pageSize":100}`
	encrypted, err := crypto.RSAEncrypt(listJSON)
	if err != nil {
		fmt.Printf("[-] Encrypt error: %v\n", err)
		os.Exit(1)
	}

	result, err := soho.SohoRequest("/cc/cloudPc/list/v6", encrypted, cfg.SohoToken, cfg.UserID)
	if err != nil {
		fmt.Printf("[-] Get cloud PC list error: %v\n", err)
		os.Exit(1)
	}
	code, _ := result["code"].(float64)
	if code != 2000 {
		fmt.Printf("[-] Get cloud PC list failed: %v\n", result["msg"])
		os.Exit(1)
	}
	data, _ := result["data"].(map[string]any)
	listRaw, _ := data["list"].([]any)
	if len(listRaw) == 0 {
		fmt.Println("[-] No cloud PC found for this account")
		os.Exit(1)
	}

	var selectedPC map[string]any
	if len(listRaw) == 1 {
		selectedPC, _ = listRaw[0].(map[string]any)
	} else {
		fmt.Printf("[*] Found %d cloud PCs:\n", len(listRaw))
		for i, item := range listRaw {
			pc, _ := item.(map[string]any)
			fmt.Printf("    [%d] %v (%v) - %v\n", i, pc["vmName"], pc["skuSpec"], pc["vmStatusShow"])
		}
		fmt.Print("[?] Select [0]: ")
		scanner.Scan()
		idxStr := strings.TrimSpace(scanner.Text())
		idx := 0
		if idxStr != "" {
			fmt.Sscanf(idxStr, "%d", &idx)
		}
		if idx < 0 || idx >= len(listRaw) {
			idx = 0
		}
		selectedPC, _ = listRaw[idx].(map[string]any)
	}

	userServiceID, _ := selectedPC["userServiceId"].(string)
	if userServiceID == "" {
		if v, ok := selectedPC["userServiceId"].(float64); ok {
			userServiceID = fmt.Sprintf("%.0f", v)
		}
	}
	cfg.UserServiceID = userServiceID
	fmt.Printf("[+] Cloud PC: %v (userServiceId=%s)\n", selectedPC["vmName"], userServiceID)

	// Get vmId
	fmt.Println("[*] Getting vmId...")
	authJSON := fmt.Sprintf(`{"userServiceId":"%s"}`, userServiceID)
	encrypted, err = crypto.RSAEncrypt(authJSON)
	if err != nil {
		fmt.Printf("[-] Encrypt error: %v\n", err)
		os.Exit(1)
	}

	result, err = soho.SohoRequest("/cc/getFirmAuth/v1", encrypted, cfg.SohoToken, cfg.UserID)
	if err != nil {
		fmt.Printf("[-] getFirmAuth error: %v\n", err)
		os.Exit(1)
	}
	code, _ = result["code"].(float64)
	if code != 2000 {
		fmt.Printf("[-] getFirmAuth failed: %v\n", result["msg"])
		os.Exit(1)
	}

	data, _ = result["data"].(map[string]any)
	cfg.VMID, _ = data["vmId"].(string)
}
