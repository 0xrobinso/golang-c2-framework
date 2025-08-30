package main

import (
	"c2-framework/internal/server"
	"flag"
	"fmt"
	"os"
)

func main() {
	var port = flag.String("port", "8443", "Server port")
	var noTLS = flag.Bool("no-tls", false, "Disable TLS encryption")
	var help = flag.Bool("help", false, "Show help")
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	useTLS := !*noTLS
	if useTLS {
		checkTLSCertificates()
	}

	srv := server.NewServer(*port, useTLS)
	srv.Start()
}

func showHelp() {
	fmt.Println("C2 Framework Server")
	fmt.Println("Usage: c2-server [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -port string    Server port (default: 8443)")
	fmt.Println("  -no-tls        Disable TLS encryption")
	fmt.Println("  -help          Show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  c2-server                    # Start server on port 8443 with TLS")
	fmt.Println("  c2-server -port=9000         # Start server on port 9000")
	fmt.Println("  c2-server -no-tls            # Start server without TLS")
}

func checkTLSCertificates() {
	if _, err := os.Stat("server.crt"); os.IsNotExist(err) {
		fmt.Println("⚠️  TLS certificates not found!")
		fmt.Println("To generate self-signed certificates, run:")
		fmt.Println("openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
		fmt.Println()
		fmt.Println("Or use -no-tls flag to start without encryption")
		os.Exit(1)
	}
}