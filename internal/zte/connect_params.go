package zte

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type ConnectParams struct {
	Raw         string
	Args        map[string]string
	Host        string
	Port        int
	Key         string
	VMID        string
	AccessToken string
	ProxySport  int
	VMIP        string
}

func DecodeConnectParams(connectStr string) (*ConnectParams, error) {
	plain, err := DecodeConnectString(connectStr)
	if err != nil {
		return nil, err
	}
	return ParseConnectParams(plain)
}

func ParseConnectParams(raw string) (*ConnectParams, error) {
	tokens, err := splitCommandLine(raw)
	if err != nil {
		return nil, err
	}
	args := make(map[string]string)
	for i := 0; i < len(tokens); i++ {
		key := tokens[i]
		if !strings.HasPrefix(key, "-") {
			continue
		}
		value := "true"
		if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") {
			i++
			value = tokens[i]
		}
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = decoded
		}
		args[key] = value
	}

	params := &ConnectParams{
		Raw:         raw,
		Args:        args,
		Host:        args["-h"],
		Key:         args["-k"],
		VMID:        args["--vmid"],
		AccessToken: args["--accessToken"],
		VMIP:        args["--vmip"],
	}
	params.Port, _ = strconv.Atoi(args["-p"])
	params.ProxySport, _ = strconv.Atoi(args["--proxy-sport"])

	if params.Host == "" {
		return nil, fmt.Errorf("connectStr missing -h host")
	}
	if params.Port == 0 {
		return nil, fmt.Errorf("connectStr missing -p port")
	}
	if params.VMID == "" {
		return nil, fmt.Errorf("connectStr missing --vmid")
	}
	return params, nil
}

func splitCommandLine(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	var quote rune
	escaped := false

	flush := func() {
		if b.Len() == 0 {
			return
		}
		out = append(out, b.String())
		b.Reset()
	}

	for _, r := range s {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t' || r == '\r' || r == '\n':
			flush()
		default:
			b.WriteRune(r)
		}
	}
	if escaped {
		b.WriteRune('\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in connectStr")
	}
	flush()
	return out, nil
}
