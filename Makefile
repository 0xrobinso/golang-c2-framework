.PHONY: build clean server client certs help

all: build

build: server client

server:
	@echo "Building C2 Server..."
	go build -o bin/c2-server ./cmd/server
	@echo "Server built: bin/c2-server"

client:
	@echo "Building C2 Client..."
	go build -o bin/c2-client ./cmd/client
	@echo "Client built: bin/c2-client"

build-all:
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build -o bin/c2-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -o bin/c2-client-linux-amd64 ./cmd/client
	GOOS=windows GOARCH=amd64 go build -o bin/c2-server-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build -o bin/c2-client-windows-amd64.exe ./cmd/client
	GOOS=darwin GOARCH=amd64 go build -o bin/c2-server-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build -o bin/c2-client-darwin-amd64 ./cmd/client
	@echo "Cross-platform builds complete"

agents:
	@echo "Building standalone agents..."
	mkdir -p agents/
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o agents/agent-windows.exe ./cmd/client
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o agents/agent-linux ./cmd/client
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o agents/agent-macos ./cmd/client
	@echo "Standalone agents built in agents/ directory"

certs:
	@echo "Generating TLS certificates..."
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
	@echo "Certificates generated: server.crt, server.key"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/ agents/
	rm -f server.crt server.key
	rm -f temp_agent.go
	@echo "Clean complete"

setup:
	@echo "Setting up project structure..."
	mkdir -p cmd/server cmd/client internal/common internal/server internal/client bin agents
	@echo "Project structure created"

run-server: server certs
	@echo "Starting C2 Server..."
	./bin/c2-server

run-client: client
	@echo "Starting C2 Client..."
	./bin/c2-client

help:
	@echo "C2 Framework Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build      - Build both server and client"
	@echo "  server     - Build server binary only"
	@echo "  client     - Build client binary only"
	@echo "  build-all  - Build for multiple platforms"
	@echo "  agents     - Build standalone agents for all platforms"
	@echo "  certs      - Generate TLS certificates"
	@echo "  setup      - Create project directory structure"
	@echo "  clean      - Remove build artifacts"
	@echo "  run-server - Build and run server"
	@echo "  run-client - Build and run client"
	@echo "  help       - Show this help"
