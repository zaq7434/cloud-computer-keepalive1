package main

import (
	"cloud-computer-keepalive/cmd"
	"fmt"
	"os"
)

const banner = `
 ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ██████╗  ██████╗
██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝
██║     ██║     ██║   ██║██║   ██║██║  ██║██████╔╝██║
██║     ██║     ██║   ██║██║   ██║██║  ██║██╔═══╝ ██║
╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝██║     ╚██████╗
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝      ╚═════╝
─────────────────────────────────────────────────────────────
  ** 免责声明 / Disclaimer **

  本程序仅供学习和研究网络协议使用
  严禁用于任何商业用途或非法用途

  本程序完全免费，如果您是通过任何平台付费购买
  可能导致您的账号、隐私等敏感信息泄露，与原作者无关

  详细原理: https://codming.com/posts/cmcc-cloud-computer-keepalive/
─────────────────────────────────────────────────────────────
`

func main() {
	fmt.Print(banner)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <login|keepalive> [options]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  login                Interactive login")
		fmt.Fprintln(os.Stderr, "  keepalive            Keep cloud PC alive")
		fmt.Fprintln(os.Stderr, "    --duration N       Hold connection for N seconds (default: 120)")
		fmt.Fprintln(os.Stderr, "    --forever          Persistent connection (Ctrl+C to exit)")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "login":
		cmd.Login()
	case "keepalive":
		cmd.Keepalive(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
