package common

import "time"


type Message struct {
	Type      string `json:"type"`
	Command   string `json:"command"`
	Result    string `json:"result"`
	ClientID  string `json:"client_id"`
	Timestamp int64  `json:"timestamp"`
}
type ClientInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	User     string `json:"user"`
	IP       string `json:"ip"`
}


type Client struct {
	ID       string
	Conn     interface{}
	LastSeen time.Time
	Info     ClientInfo
}