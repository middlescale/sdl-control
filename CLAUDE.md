# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Architecture Overview

The sdl-control project is a Go reimplementation of the control plane for the VNT (Virtual Network Tunnel) system, designed to decouple the control plane from the data forwarding plane. The architecture follows a layered approach:

### Control Plane vs Data Plane Separation
- **Control Plane** (`sdl-control`): Handles authentication, registration, session management, and status synchronization
- **Data Plane**: Independent gateway clusters responsible for packet forwarding and relaying
- **Client** (`sdl`): Communicates with control plane via QUIC protocol

### Core Components
- `main.go`: Service startup entry point, handles configuration loading, TLS initialization, and QUIC server startup
- `config/`: Configuration definitions and default configuration files
- `handlers/`: QUIC, WebSocket, and status interface handlers
- `control/`: Core logic for handshake, registration, virtual IP allocation
- `protocol/` & `proto/`: Protocol definitions and protobuf-generated code

## Development Commands

### Build
```bash
cd sdl-control
make build                    # Build binary to ./sdl-control
make run                      # Run the compiled binary
make clean                    # Remove binary
make proto                    # Regenerate protobuf Go code (requires protoc)
```

### Testing
```bash
go test ./...                 # Run all tests
go test ./control             # Run specific package tests
go test -v ./control          # Run tests with verbose output
```

### Protocol Generation
- When modifying `.proto` files, run `make proto` to regenerate Go code
- Requires protoc and protoc-gen-go plugins installed

## Key Features

### Status Reporting & Online Semantics
- `ControlOnline`: Indicates client's active connection to control plane (refreshed by registration, control pings, status reports)
- `DataPlaneReachable`: Indicates data plane reachability (currently based on `ClientStatusInfo.p2p_list` non-emptiness)
- `DeviceStatus`: Maps to `ControlOnline` externally (0=online, 1=offline)

### Configuration Options
- Default: Reads `config/config.json` (falls back to `config.json`)
- Environment variables override configuration files
- Supports automatic TLS certificate acquisition via Let's Encrypt
- Client certificate verification (mTLS) support

### Protocol Support
- Primary: QUIC protocol for control plane communication
- Planned: Integration with data plane via separate gateway services
- TLS 1.3 with custom ALPN protocol "sdl-control"

## Code Structure

### Package Dependencies
- `github.com/gorilla/websocket` - WebSocket communication
- `github.com/quic-go/quic-go` - QUIC protocol implementation
- `golang.org/x/crypto` - Cryptographic utilities
- `google.golang.org/protobuf` - Protocol buffer support

### Protocol Flow
1. Handshake: Client initiates connection and exchanges capabilities
2. Registration: Client registers with device information
3. Status Updates: Periodic reporting of client status including NAT type and traffic info
4. Device Lists: Distribution of network topology to clients

### Security Features
- Capability negotiation during handshake
- QUIC-based secure transport
- Optional client certificate verification (mTLS)
- Automatic certificate management

## Administrator Commands

The `sdl-admin` tool provides administrative functionality through a Unix Domain Socket (default: `/tmp/sdl-control-admin.sock`):

```bash
./sdl-admin user create --id user1 --group sales.ms.net
./sdl-admin user create -u user1
./sdl-admin user list [--id/-u 'user-*'] [--name/-n huang]
./sdl-admin device list --id/-u <user_id>
./sdl-admin device issue-auth-ticket --id/-u <user_id> --group/-g sales.ms.net
./sdl-admin device extend-expiry --id/-u <user_id> --device-id/-d <device_id>
./sdl-admin gateway --list
./sdl-admin gateway --enlist gw-1
./sdl-admin gateway --delist gw-1
```

Note: The `--group` parameter can accept short names (e.g., `sales`, which gets automatically completed to `sales.<user-domain>`) or FQDN (e.g., `sales.ms.net`, which gets validated to ensure it belongs to the user's domain).

Gateway registration/keepalive uses shared-secret HMAC auth plus separate admin approval: every `GatewayReportRequest` must carry `nonce + signature`, where signature is HMAC-SHA256 over the protobuf proof `(gateway_id, endpoint, capabilities, report_unix_ms, nonce)` using `gateway_ticket_secret`. Admin approval via `gateway --enlist` remains separate from authentication, and replay/freshness failures must be rejected explicitly.

### Configuration Example
```json
{
  "default_domain": "ms.net",
  "default_gateway_id": "default",
  "domains": {
    "ms.net": {
      "groups": {
        "sales": { "gateway": "10.26.0.1", "netmask": "255.255.255.0" },
        "marketing": { "gateway": "10.27.0.1", "netmask": "255.255.255.0" }
      }
    },
    "dev.net": {
      "groups": {
        "qa": { "gateway": "10.28.0.1", "netmask": "255.255.255.0" }
      }
    }
  },
  "listen_addr": ":4433",
  "cert_cache_dir": "./cert-cache"
}
```

### Environment Variables (higher priority than config files)
- `CONFIG_PATH`
- `LISTEN_ADDR`
- `TLS_CERT` / `TLS_KEY`
- `AUTOCERT_DOMAIN`
- `CERT_CACHE_DIR`
- `TLS_CLIENT_CA`
- `TLS_REQUIRE_CLIENT_CERT`
- `LOG_LEVEL`
- `ADMIN_SOCKET_PATH` (Unix Domain Socket path for admin commands, default `/tmp/sdl-control-admin.sock`)
