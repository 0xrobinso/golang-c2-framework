package main

import (
	"c2-framework/internal/client"
	"flag"
	"fmt"
)

func main() {
	var host = flag.String("host", "localhost", "Server host")
	var port = flag.String("port", "8443", "Server port")
	var clientID = flag.String("id", "", "Client ID (auto-generated if empty)")
	var help = flag.Bool("help", false, "Show help")
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	c := client.NewClient(*host, *port, *clientID)
	c.Start()
}

func showHelp() {
	fmt.Println("C2 Framework Client")
	fmt.Println("Usage: c2-client [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -host string    Server host (default: localhost)")
	fmt.Println("  -port string    Server port (default: 8443)")
	fmt.Println("  -id string      Client ID (auto-generated if empty)")
	fmt.Println("  -help          Show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  c2-client                           # Connect to localhost:8443")
	fmt.Println("  c2-client -host=192.168.1.100       # Connect to specific host")
	fmt.Println("  c2-client -id=workstation-01        # Use custom client ID")
}
