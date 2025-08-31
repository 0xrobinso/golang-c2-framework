package common

import "time"

// Message represents communication between server and client
type Message struct {
	Type      string `json:"type"`
	Command   string `json:"command"`
	Result    string `json:"result"`
	ClientID  string `json:"client_id"`
	Timestamp int64  `json:"timestamp"`
}

// ClientInfo holds client system information
type ClientInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	User     string `json:"user"`
	IP       string `json:"ip"`
}

// Client represents a connected client
type Client struct {
	ID       string
	Conn     interface{}
	LastSeen time.Time
	Info     ClientInfo
}