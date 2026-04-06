// Package qmp implements the QEMU Monitor Protocol client.
package qmp

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Send connects to a QMP Unix socket, negotiates capabilities,
// sends a JSON command, and returns the response.
func Send(socketPath, commandJSON string, timeoutSecs uint64) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	timeout := time.Duration(timeoutSecs) * time.Second
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// 1. Read QMP greeting
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.Contains(line, `"QMP"`) {
		return "", fmt.Errorf("unexpected QMP greeting: %s", strings.TrimSpace(line))
	}

	// 2. Send qmp_capabilities
	if _, err := io.WriteString(conn, "{\"execute\":\"qmp_capabilities\"}\n"); err != nil {
		return "", err
	}

	// 3. Read capabilities response
	line, err = reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.Contains(line, `"return"`) {
		return "", fmt.Errorf("qmp_capabilities failed: %s", strings.TrimSpace(line))
	}

	// 4. Send user command
	if _, err := io.WriteString(conn, commandJSON+"\n"); err != nil {
		return "", err
	}

	// 5. Read response, skip async events
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("QMP connection closed before response")
		}
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, `"return"`) || strings.Contains(trimmed, `"error"`) {
			return trimmed, nil
		}
	}
}
