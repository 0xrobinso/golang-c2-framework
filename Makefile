# Makefile for C2 Framework

.PHONY: build clean server client certs help

# Default target
all: build

# Build both binaries
build: server client

# Build server binary
server:
	@echo "🔨 Building C2 Server..."
	go build -o bin/c2-server ./cmd/server
	@echo "✅ Server built: bin/c2-server"

# Build client binary
client:
	@echo "🔨 Building C2 Client..."
	go build -o bin/c2-client ./cmd/client
	@echo "✅ Client built: bin/c2-client"

# Build for multiple platforms
build-all:
	@echo "🔨 Building for multiple platforms..."
	
	# Linux
	GOOS=linux GOARCH=amd64 go build -o bin/c2-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -o bin/c2-client-linux-amd64 ./cmd/client
	
	# Windows
	GOOS=windows GOARCH=amd64 go build -o bin/c2-server-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build -o bin/c2-client-windows-amd64.exe ./cmd/client
	
	# macOS
	GOOS=darwin GOARCH=amd64 go build -o bin/c2-server-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build -o bin/c2-client-darwin-amd64 ./cmd/client
	
	@echo "✅ Cross-platform builds complete"

# Generate standalone agents
agents:
	@echo "🔨 Building standalone agents..."
	mkdir -p agents/
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o agents/agent-windows.exe ./cmd/client
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o agents/agent-linux ./cmd/client
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o agents/agent-macos ./cmd/client
	@echo "✅ Standalone agents built in agents/ directory"

# Generate TLS certificates
certs:
	@echo "🔐 Generating TLS certificates..."
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
	@echo "✅ Certificates generated: server.crt, server.key"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf bin/ agents/
	rm -f server.crt server.key
	rm -f temp_agent.go
	@echo "✅ Clean complete"

# Create directory structure
setup:
	@echo "📁 Setting up project structure..."
	mkdir -p cmd/server cmd/client internal/common internal/server internal/client bin agents
	@echo "✅ Project structure created"

# Run server
run-server: server certs
	@echo "🚀 Starting C2 Server..."
	./bin/c2-server

# Run client
run-client: client
	@echo "🚀 Starting C2 Client..."
	./bin/c2-client

# Show help
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