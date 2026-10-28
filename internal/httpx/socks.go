package httpx

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

// socks5Dialer returns a dial function implementing the SOCKS5 protocol
// (RFC 1928) with optional username/password authentication (RFC 1929).
func socks5Dialer(proxy *url.URL, timeout time.Duration) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if proxy.Host == "" {
		return nil, fmt.Errorf("socks5 proxy is missing a host")
	}
	proxyAddr := proxy.Host
	if proxy.Port() == "" {
		proxyAddr = net.JoinHostPort(proxy.Hostname(), "1080")
	}
	auth := proxy.User
	dialer := &net.Dialer{Timeout: timeout}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("socks5 dial %s: %w", proxyAddr, err)
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if err := socks5Handshake(conn, addr, auth); err != nil {
			conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}, nil
}

func socks5Handshake(conn net.Conn, target string, auth *url.Userinfo) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("socks5 target: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("socks5 target port %q invalid", portStr)
	}

	methods := []byte{0x00}
	if auth != nil {
		methods = append(methods, 0x02)
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 greeting response: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5: unexpected version %d", resp[0])
	}

	switch resp[1] {
	case 0x00:
		// no authentication
	case 0x02:
		if auth == nil {
			return fmt.Errorf("socks5: proxy requires authentication")
		}
		user := auth.Username()
		pass, _ := auth.Password()
		if len(user) > 255 || len(pass) > 255 {
			return fmt.Errorf("socks5: credentials too long")
		}
		buf := []byte{0x01, byte(len(user))}
		buf = append(buf, user...)
		buf = append(buf, byte(len(pass)))
		buf = append(buf, pass...)
		if _, err := conn.Write(buf); err != nil {
			return fmt.Errorf("socks5 auth: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("socks5 auth response: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5: authentication failed")
		}
	case 0xFF:
		return fmt.Errorf("socks5: no acceptable authentication method")
	default:
		return fmt.Errorf("socks5: unsupported auth method %d", resp[1])
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5 connect response: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks5: unexpected version %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connection failed (%s)", socksReply(head[1]))
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		one := make([]byte, 1)
		if _, err := io.ReadFull(conn, one); err != nil {
			return err
		}
		skip = int(one[0])
	default:
		return fmt.Errorf("socks5: unknown address type %d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return fmt.Errorf("socks5: read bind address: %w", err)
	}
	return nil
}

func socksReply(code byte) string {
	switch code {
	case 1:
		return "general failure"
	case 2:
		return "connection not allowed"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	}
	return "unknown error"
}
