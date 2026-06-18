# sdl-control

`sdl-control` is the control plane for SDL (Software Defined LAN). It authenticates users and devices, assigns virtual network identity, tracks online state, and distributes gateway/DNS policy to SDL clients. Packet forwarding is handled by separate `sdl-gateway` instances, so the control plane and data plane can be deployed and scaled independently.

SDL is an overlay LAN system: it connects devices across WAN, cloud VPCs, and home networks into isolated virtual networks controlled by policy.

## Architecture

```text
sdl client  <-- QUIC control session -->  sdl-control  <-- admin API -->  sdl-admin / sdl-www
    |                                      |
    |                                      +-- PostgreSQL or JSON-backed user/device state
    |
    +-- UDP / QUIC / HTTPS relay ---------->  sdl-gateway fleet
```

Main responsibilities:

- User and device authentication.
- Device registration and virtual IP allocation.
- Per-user personal network isolation.
- Gateway grant creation and refresh.
- Split DNS policy distribution.
- Runtime status, debug snapshots, and debug watch event collection.
- Local Unix socket and optional internal HTTP admin APIs.

## Repository Layout

- `main.go`: service entry point, config loading, TLS/ACME setup, command dispatch.
- `cmd/sdl-admin/`: local admin CLI.
- `config/`: configuration model, validation, and default config.
- `control/`: registration, network identity, IP allocation, DNS, gateway grants, debug collection, and user/device state.
- `handlers/`: QUIC/HTTP3 control handlers plus admin APIs.
- `proto/`: protocol definitions.
- `protocol/`: packet helpers and generated protobuf code.

## Build

```bash
make build
```

This creates:

- `./sdl-control`
- `./sdl-admin`

Useful Make targets:

```bash
make run              # run ./sdl-control
make migrate-schema   # run PostgreSQL migrations through sdl-control migrate
make proto            # regenerate protobuf Go code
make clean            # remove local binaries
```

Run tests:

```bash
go test ./...
```

## Configuration

By default the service reads `config/config.json`, falling back to `config.json`.

Minimal example:

```json
{
  "default_domain": "ms.net",
  "default_gateway_id": "default",
  "gateway_ticket_secret": "change-me",
  "dns_service_addr": "127.0.0.1:53",
  "domains": {
    "ms.net": {
      "groups": {
        "default": {
          "gateway": "10.26.0.1",
          "netmask": "255.255.255.0",
          "dns_service_ip": "10.26.0.53"
        },
        "user": {
          "gateway": "10.26.0.1",
          "netmask": "255.255.255.0",
          "dns_service_ip": "10.26.0.53"
        }
      }
    }
  },
  "listen_addr": ":443",
  "autocert_http_addr": ":80",
  "autocert_email": "admin@example.com",
  "cert_cache_dir": "./cert-cache"
}
```

Important fields:

- `default_domain`: domain used when a user or group does not specify one.
- `default_gateway_id`: gateway ID used as the default gateway. The default gateway report must come from `gateway.middlescale.net`.
- `gateway_ticket_secret`: shared HMAC secret used for gateway reports and gateway access tickets.
- `dns_service_addr`: real DNS backend address from the control process perspective, for example `sdl-dns:53` in compose.
- `dns_service_ip`: logical DNS service IP advertised to clients.
- `dns_servers`: optional split DNS server list sent to clients.
- `dns_match_domains`: optional split DNS match suffixes sent to clients.
- `domains.<domain>.groups.<group>`: virtual network settings for a group, including gateway IP and netmask.
- `listen_addr`: shared HTTP/3 listener for `/control` and normal HTTP APIs.
- `tls_cert_path` / `tls_key_path`: static TLS certificate files.
- `client_ca_path` / `require_client_cert`: optional client certificate validation.

If `dns_servers` or `dns_match_domains` are omitted, control derives them from the group DNS service IP and domain.

## Environment Variables

Environment variables override the config file.

- `CONFIG_PATH`
- `LISTEN_ADDR`
- `TLS_CERT`
- `TLS_KEY`
- `DATABASE_URL`
- `AUTOCERT_DOMAIN`
- `AUTOCERT_HTTP_ADDR`
- `AUTOCERT_EMAIL`
- `CERT_CACHE_DIR`
- `TLS_CLIENT_CA`
- `TLS_REQUIRE_CLIENT_CERT`
- `DEBUG_COLLECT_DIR`
- `DEBUG_COLLECT_KEEP_PER_DEVICE`
- `LOG_LEVEL`
- `ADMIN_SOCKET_PATH`
- `ADMIN_HTTP_ADDR`
- `ADMIN_HTTP_TOKEN`
- `UM_STORE_JSON_PATH`
- `UM_STORE_MIGRATION_JSON_PATH`

## Database

When `DATABASE_URL` is set, PostgreSQL is the source of truth for user and device state. The running service checks that required migrations exist; it does not silently initialize missing schema.

Run migrations before starting the service:

```bash
DATABASE_URL=postgres://user:password@host:5432/dbname?sslmode=disable \
  make migrate-schema
```

Storage modes:

- With `DATABASE_URL`: use PostgreSQL `um_*` tables.
- Without `DATABASE_URL`: use JSON state from `UM_STORE_JSON_PATH`.
- `UM_STORE_MIGRATION_JSON_PATH`: one-time JSON-to-PostgreSQL import when the `um_*` tables are empty.

## TLS and ACME

If `TLS_CERT` / `TLS_KEY` or `tls_cert_path` / `tls_key_path` are provided, `sdl-control` uses those files.

Otherwise it can use built-in ACME:

```bash
AUTOCERT_DOMAIN=control.example.com \
AUTOCERT_HTTP_ADDR=:80 \
AUTOCERT_EMAIL=admin@example.com \
LISTEN_ADDR=:443 \
./sdl-control
```

Requirements:

- `AUTOCERT_DOMAIN` resolves to the control host.
- TCP port 80 reaches the built-in HTTP-01 challenge server.
- The QUIC UDP port from `LISTEN_ADDR` is reachable by clients.
- `CERT_CACHE_DIR` is persistent across restarts.

## Admin CLI

`sdl-admin` talks to `sdl-control` through the local Unix domain socket. The default socket is `/tmp/sdl-control-admin.sock`; override it with `--socket` or `SDL_ADMIN_SOCKET`.

Examples:

```bash
./sdl-admin user create --id user1 --group sales.ms.net
./sdl-admin user create -u user1
./sdl-admin user list
./sdl-admin user list --id 'sdl-*'
./sdl-admin user list --name huang

./sdl-admin device list --id <user_id>
./sdl-admin device issue-auth-ticket -u <user_id> -g sales.ms.net
./sdl-admin device extend-expiry -u <user_id> --device-id <device_id> --ttl-seconds 2592000
./sdl-admin device extend-expiry -u <user_id> --all --ttl-seconds 2592000

./sdl-admin gateway --list
./sdl-admin gateway --enlist gw-1
./sdl-admin gateway --delist gw-1

./sdl-admin dnsDomains
./sdl-admin dnsSnapshot --domain ms.net

./sdl-admin collectDebug --name laptop-01
./sdl-admin collectDebug --name laptop-01 --group sales.ms.net --sections runtime,gateway,peers,routes,nat,traffic
./sdl-admin startDebugWatch --name laptop-01 --sections gateway,icmp,punch,route,runtime --durationSec 300
./sdl-admin stopDebugWatch --name laptop-01
```

Notes:

- `user create --group` accepts short group names such as `sales` and FQDNs such as `sales.ms.net`.
- `user list --id/-u` filters by user ID with `*` and `?` wildcard support.
- `user list --name/-n` filters by display name case-insensitively; without wildcards it performs substring matching.
- `device issue-auth-ticket` defaults to group `default.ms.net` and TTL `300` seconds.
- `device list` shows all authorized devices for a user, including offline devices and auth expiry.
- `device extend-expiry` can extend one device or all devices for the user.

## Internal Admin HTTP API

For split deployment with `sdl-www`, enable the internal admin HTTP API:

```bash
ADMIN_HTTP_ADDR=0.0.0.0:8081
ADMIN_HTTP_TOKEN=<strong-token>
```

Supported endpoints include:

- `POST /admin/v1/create_user`
- `GET /admin/v1/list_users?id=sdl-*&name=huang`
- `POST /admin/v1/issue_auth_ticket`
- `GET /admin/v1/list_devices?user_id=<id>`
- `POST /admin/v1/extend_device_expiry`

Requests must include:

```text
Authorization: Bearer <ADMIN_HTTP_TOKEN>
```

Bind this listener only on a private network and restrict access to trusted hosts such as `sdl-www`.

## Gateway Model

Gateway reports and grants are channel-aware.

Gateway registration has two layers:

1. HMAC authentication. Each `GatewayReportRequest` includes `nonce + signature`. The signature is HMAC-SHA256 over the protobuf report proof using `gateway_ticket_secret`.
2. Admin approval. Non-default gateways must be approved with `sdl-admin gateway --enlist <gateway-id>` before clients receive grants for them.

Gateway state:

- The default gateway is identified by `default_gateway_id`.
- The default gateway host must be `gateway.middlescale.net`.
- Approved gateways use a lease/keepalive model; expired gateways stop being sent to clients.
- `sdl-admin gateway --delist <id>` removes approval and triggers gateway grant refresh.

Gateway channels:

- UDP is the default client-to-gateway data channel.
- UDP grants include `udp_public_key` and `udp_key_id` for secure channel bootstrap.
- QUIC/HTTPS channels may also be reported and distributed for fallback.

## Device Authentication

Clients authenticate devices with:

```bash
sdl auth --userId <user-id> --group <group.ms.net> <ticket>
```

The ticket is issued by `sdl-admin device issue-auth-ticket`. After successful authentication, the device can register into the network. The default auth validity is 30 days unless extended by admin commands.

## Debug Collection

`collectDebug` requests a structured snapshot from an online device and stores it under `DEBUG_COLLECT_DIR` (default `./data/debug-collect`). The latest snapshot is also written as `latest.json`.

Supported snapshot sections include:

- `runtime`
- `gateway`
- `peers`
- `routes`
- `nat`
- `traffic`

`startDebugWatch` / `stopDebugWatch` create an asynchronous event stream under the watch directory. Current event sections cover gateway auth/connect, ICMP path events, punch events, route repunch triggers, and runtime watch lifecycle.

## Release Image

The repository includes a `release-image` GitHub Actions workflow:

- Tag push publishes `ghcr.io/<owner>/sdl-control:<tag>`.
- `workflow_dispatch` can publish a chosen `source_ref` as `release_tag`.

The image is consumed by `sdl-integration` release gates and `sdl-deploy`.

## Roadmap

- Keep `sdl-control` and normal HTTP APIs on the same HTTP/3 listener.
- Continue tightening the SDL control protocol around auth, registration, status, gateway grants, and DNS policy.
- Keep forwarding out of the control process and rely on independently deployable gateway fleets.
