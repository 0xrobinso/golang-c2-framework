
# C2 Framework

A simple Command and Control (C2) framework written in Go for educational and portfolio purposes.

## Features

- 🔒 **TLS Encryption** - Secure client-server communication
- 👥 **Multi-client Support** - Handle multiple connected clients
- 🖥️ **Interactive CLI** - User-friendly command-line interface
- 🌐 **Cross-platform** - Works on Windows, Linux, and macOS
- ⚡ **Real-time Communication** - Live command execution and results
- 💓 **Heartbeat Monitoring** - Track client connectivity status
- 🎯 **Selective Targeting** - Execute commands on specific clients
- 📢 **Broadcast Commands** - Send commands to all connected clients

## Quick Start

### 1. Setup Project Structure
```bash
make setup
```

### 2. Build Binaries
```bash
make build
```

### 3. Generate TLS Certificates (Optional but Recommended)
```bash
make certs
```

### 4. Start the Server
```bash
./bin/c2-server
```

### 5. Connect Clients
```bash
./bin/c2-client
```

## Usage

### Server Commands
- `help` - Show available commands
- `list` - List all connected clients
- `select <client_id>` - Enter interactive mode with a client
- `broadcast <command>` - Send command to all clients
- `remove <client_id>` - Disconnect a client
- `status` - Show server status
- `clear` - Clear screen
- `quit` - Shutdown server

### Client Commands (when selected)
- `sysinfo` - Get detailed system information
- `pwd` - Show current working directory
- `ls`/`dir` - List directory contents
- `cd <directory>` - Change directory
- `whoami` - Show current user
- `ps`/`processes` - List running processes
- Any system command (executed via shell)

## Building for Multiple Platforms

```bash
make build-all
```

This creates binaries for:
- Linux (amd64)
- Windows (amd64) 
- macOS (amd64)

## Security Features

### TLS Encryption
The framework supports TLS encryption for secure communications. Generate certificates with:
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
```

### Fallback Mode
If TLS certificates are not available, the framework automatically falls back to an insecure connection with a warning.

## Architecture

```
c2-framework/
├── cmd/
│   ├── server/          # Server binary source
│   └── client/          # Client binary source
├── internal/
│   ├── common/          # Shared types and utilities
│   ├── server/          # Server implementation
│   └── client/          # Client implementation
├── bin/                 # Compiled binaries
├── go.mod              # Go module file
├── Makefile            # Build automation
└── README.md           # This file
```

## Example Session

### Starting the Server
```bash
$ ./bin/c2-server
C2 Framework v1.0 - Command & Control
C2 Server started on port 8443 (TLS Encrypted)

C2> list
No clients connected

C2> 
New client connected: workstation_1693123456 (john@workstation)

C2> list
Connected Clients (1):
Client ID           OS/Arch      Hostname    User    Last Seen
workstation_...     linux/amd64  workstation john    2s

C2> select workstation_1693123456
Selected client: workstation_1693123456 (workstation)
Type 'back' to return to main menu

workstation> sysinfo
[workstation_1693123456] Result:
System Information:
OS: linux
Architecture: amd64
Hostname: workstation
User: john
Go Version: go1.21.0

workstation> pwd
[workstation_1693123456] Result:
Current directory: /home/john

workstation> back
C2> 

```

## Development

### Prerequisites
- Go 1.21 or later
- OpenSSL (for certificate generation)
- Make (optional, for build automation)

### Manual Build
```bash
# Server
go build -o c2-server ./cmd/server

# Client  
go build -o c2-client ./cmd/client
```

## Educational Purpose

This framework demonstrates several important concepts:

1. **Network Programming** - TCP sockets, TLS encryption
2. **Concurrent Programming** - Goroutines for handling multiple clients
3. **JSON Communication** - Structured data exchange
4. **System Interaction** - OS command execution and system information gathering
5. **CLI Development** - Interactive command-line interfaces
6. **Error Handling** - Robust error handling and recovery
7. **Cross-platform Development** - Code that works across different operating systems

## License

This project is for educational purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Roadmap

Future enhancements could include:
- File transfer capabilities
- Plugin system for custom modules
- Web-based management interface
- Database logging of activities
- Configuration file support
- Advanced encryption options
- Client persistence mechanisms