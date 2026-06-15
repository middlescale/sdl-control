# sdl-control

`sdl-control` 是 `sdl` 的 控制面项目，目标是将控制面与网关转发面解耦：客户端和 gateway 通过 **QUIC bi-stream control session** 与控制服务通信完成认证与状态同步，普通 HTTP API 直接复用同一个 HTTP/3 监听口。

从产品语义上看，这个项目更贴近 **SDL (Software Defined LAN)**：通过控制平面把分散在 WAN / Internet 上的节点组织成一个 overlay LAN，而不是传统 SD-WAN 的选路优化产品。

## 目标架构分层

- `vnts` / `sdl-control`（Control Plane）：
  - 用户/设备认证
  - 注册与会话管理
  - 控制面在线状态、设备列表、NAT 信息等状态更新
- `gateway` 集群（Data Plane）：
  - 数据包转发与中继
  - 横向扩展与高可用
- `sdl` 客户端：
  - 通过 QUIC bi-stream 与控制面交互
  - 按控制面下发信息选择/切换数据路径

> 过渡说明：仓库、二进制与主要运行时命名已经切到 `sdl*`；仍有少量内部实现/历史术语保留旧命名，后续会继续收口。

## 在线状态语义（当前实现）

- `ControlOnline`：表示客户端是否与控制面保持活跃（注册、控制 ping、状态上报都会刷新）。
- `DataPlaneReachable`：表示数据面可达性（当前按 `ClientStatusInfo.p2p_list` 是否非空判定）。
- `DeviceStatus` 当前按 `ControlOnline` 对外映射：在线为 `0`，离线为 `1`。

> 说明：当前 `DataPlaneReachable` 语义是“P2P 可达”，尚未包含仅 relay/gateway 可达场景，后续会扩展。

## 目录结构

- `main.go`：服务启动入口，加载配置、初始化 TLS，并在同一个 HTTP/3 监听上同时提供 `/control` 与普通 API。
- `config/`：配置定义与默认配置文件。
- `handlers/`：QUIC control、HTTP/3 API、WebSocket / 状态接口处理。
- `control/`：握手、注册、虚拟 IP 分配等核心控制逻辑。
- `protocol/`、`proto/`：协议定义与 protobuf 生成代码。

## 配置

默认读取 `config/config.json`（不存在时回退 `config.json`）。

示例：

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
  "listen_addr": ":443",
  "autocert_http_addr": ":80",
  "autocert_email": "admin@example.com",
  "cert_cache_dir": "./cert-cache"
}
```

可选字段：

- `autocert_domain`：启用 `autocert` 时用于签发证书的域名。
- `listen_addr`：HTTP/3 监听地址，`/control` 与普通 API 共用同一端口。
- `autocert_http_addr`：内置 ACME `HTTP-01` challenge server 监听地址，默认 `:80`。
- `autocert_email`：ACME 账户联系邮箱，可选但推荐配置。
- `default_domain`：创建用户时未指定域名时使用，默认建议 `ms.net`。
- `default_gateway_id`：默认下发给客户端的 gateway 身份标识，默认值是 `default`。control 只按这个 `gateway_id` 选择默认网关，实际地址来自 gateway 上报并落到本地 `gateway` 状态文件的 `gateway_id -> endpoint` 记录；默认网关的上报主机必须是 `gateway.middlescale.net`。
- `dns_service_ip`：为 `sdl-dns` 预留的固定虚拟 IP；可放在顶层作为默认值，也可放在 `domains.<domain>.groups.<group>` 下做 group 覆盖。普通客户端自动分配会跳过这个地址，`sdl-dns` 可在注册时显式请求它。
- `dns_service_addr`：control 本机代理 DNS 查询时转发到的实际地址，格式为 `host:port`，默认 `127.0.0.1:53`；容器化部署时通常应配置成 `sdl-dns:53`。
- `dns_servers`：给客户端 split DNS 下发的 DNS 服务器 IPv4 列表；可放在顶层作为默认值，也可放在 `domains.<domain>.groups.<group>` 下做覆盖。
- `dns_match_domains`：给客户端 split DNS 下发的域名后缀列表；可放在顶层作为默认值，也可放在 group 下做覆盖。
- `gateway_ticket_secret`：control 与 gateway 共享的密钥；control 用它对下发给客户端的 gateway ticket 做 HMAC-SHA256 签名，也用它校验 gateway 上报的 `GatewayReportRequest.signature`。
- `domains`：多域名配置，`domains.<domain>.groups.<group>` 对应子域配置，例如 `sales.ms.net`。
- `tls_cert_path` / `tls_key_path`：使用本地证书文件。
- `client_ca_path`：客户端 CA 文件路径（PEM）。
- `require_client_cert`：是否强制客户端证书校验（mTLS）。

如果 `dns_servers` / `dns_match_domains` 未显式配置，control 当前会回退为：

- `dns_servers`：当前 group 的 `dns_service_ip`，若未配置再回退到当前 group 的 `gateway`
- `dns_match_domains`：当前 domain

这里的 `dns_service_ip` 是客户端视角的**逻辑 DNS 服务 IP**，`dns_service_addr` 是 control 进程视角的**实际 DNS 服务地址**。当前实现会在客户端把发往 `dns_service_ip:53` 的 UDP 查询劫持到 control 通道，再由 control 转发到 `dns_service_addr`。

## 环境变量（优先级高于配置文件）

- `CONFIG_PATH`
- `LISTEN_ADDR`
- `TLS_CERT` / `TLS_KEY`
- `DATABASE_URL`（可选；中心 PostgreSQL 连接串，`sdl-www` 与 `sdl-control` 共用同一实例，但各自维护不同表边界；数据库 schema 迁移统一由 `sdl-control migrate` 管理）
- `AUTOCERT_DOMAIN`
- `AUTOCERT_HTTP_ADDR`
- `AUTOCERT_EMAIL`
- `CERT_CACHE_DIR`
- `TLS_CLIENT_CA`
- `TLS_REQUIRE_CLIENT_CERT`
- `DEBUG_COLLECT_DIR`（远程 debug snapshot 落盘目录，默认 `./data/debug-collect`）
- `DEBUG_COLLECT_KEEP_PER_DEVICE`（每个节点保留的历史 snapshot 数量，默认 `20`）
- `LOG_LEVEL`
- `ADMIN_SOCKET_PATH`（管理员命令本地 Unix Domain Socket 路径，默认 `/tmp/sdl-control-admin.sock`）
- `ADMIN_HTTP_ADDR`（可选；给 `sdl-www` 等内网服务使用的 HTTP 管理接口监听地址，例如 `0.0.0.0:8081`，并配合防火墙限制来源）
- `ADMIN_HTTP_TOKEN`（启用 `ADMIN_HTTP_ADDR` 时必填；内网管理接口 Bearer Token）
- `UM_STORE_JSON_PATH`（仅在未配置 `DATABASE_URL` 时作为 JSON 存储路径）
- `UM_STORE_MIGRATION_JSON_PATH`（可选；仅在 PostgreSQL `um_*` 表为空时，做一次性的 JSON -> DB 导入，导入后后续运行只使用数据库）

## 使用 Makefile 编译与运行

```bash
cd sdl-control
make build
```

编译产物为当前目录下的 `./sdl-control`。

如果启用了 `DATABASE_URL`，请先执行一次数据库迁移，再启动服务：

```bash
cd sdl-control
DATABASE_URL=postgres://... make migrate-schema
```

运行中的 `sdl-control` 不再自动建表；它只会校验数据库里已经包含 `schema_migrations` 记录和自己所需的最小 schema 版本。

### 内置 ACME / 自动续期

当未提供 `TLS_CERT` / `TLS_KEY` 或 `tls_cert_path` / `tls_key_path` 时，`sdl-control` 会自动进入内置 ACME 模式：

- control 与 HTTP/3 API 共用 `listen_addr`
- 同时额外启动一个 `HTTP-01` challenge server 在 `autocert_http_addr`（默认 `:80`）
- 证书与 ACME 账户缓存保存在 `cert_cache_dir`

最小要求：

- `autocert_domain` 指向当前 control 公网域名
- 该域名的 80 端口能到达 `sdl-control`
- `listen_addr` 对应的 QUIC UDP 端口能被客户端访问

示例：

```bash
AUTOCERT_DOMAIN=control.example.com \
AUTOCERT_HTTP_ADDR=:80 \
AUTOCERT_EMAIL=admin@example.com \
LISTEN_ADDR=:443 \
./sdl-control
```

如果你已经有现成证书，仍然可以继续走静态文件模式；只有在未提供证书文件时，才会切到内置 ACME。

常用命令：

```bash
make run     # 运行已编译二进制
make migrate-schema  # 执行统一的 PostgreSQL schema 迁移
make clean   # 删除二进制
make proto   # 重新生成 proto Go 代码（需安装 protoc 与插件）
```

会同时生成：

- `./sdl-control`
- `./sdl-admin`

## 管理员命令（sdl-admin）

`sdl-admin` 通过本机 Unix Domain Socket 调用控制端管理接口（默认 `/tmp/sdl-control-admin.sock`）。

如果 `sdl-www` 与 `sdl-control` 分机部署，可以额外启用内网 HTTP 管理接口：

- `POST /admin/v1/create_user`
- `GET /admin/v1/list_users?id=sdl-*&name=huang`
- `POST /admin/v1/issue_auth_ticket`
- `GET /admin/v1/list_devices?user_id=<id>`
- `POST /admin/v1/extend_device_expiry`

请求头需要：

```text
Authorization: Bearer <ADMIN_HTTP_TOKEN>
```

建议只绑定局域网地址，并限制为 `sdl-www` 主机访问。

示例：

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
./sdl-admin dnsDomains
./sdl-admin dnsSnapshot --domain ms.net
./sdl-admin gateway --enlist gw-1
./sdl-admin gateway --delist gw-1
./sdl-admin collectDebug --name laptop-01
./sdl-admin collectDebug --name laptop-01 --group sales.ms.net --sections runtime,gateway,peers,routes,nat,traffic
./sdl-admin startDebugWatch --name laptop-01 --sections gateway,icmp,punch,route,runtime --durationSec 300
./sdl-admin stopDebugWatch --name laptop-01
```

说明：`user create` 里的 `--group` 不传时默认是 `default`（最终会落成默认域名下的 `default.<domain>`）。`--group` 可传短名（如 `sales`，会自动补全为用户所属域名下的 `sales.<user-domain>`）；若传 FQDN（如 `sales.ms.net`），会校验其必须属于该用户所属域名。`user list` 列出全部用户；数据库模式下还会关联 `sdl-www` 用户资料显示 OAuth name 和 email。`--id/-u` 对 user ID 做大小写敏感的整串通配符匹配；`--name/-n` 不区分大小写，无通配符时按包含关系匹配，因此 `--name huang` 可以命中 `patrick huang`。两者都支持 `*` 匹配任意数量字符、`?` 匹配单个字符，并且可以同时使用。`device issue-auth-ticket` 里的 `--group` 可省略，默认是 `default.ms.net`；`--ttl-seconds` 也可省略，默认是 `300`。`device list` 会列出该用户下**全部已授权设备**，包括当前离线设备，并带上认证过期时间。`device extend-expiry` 用于把某个设备或该用户下全部设备的认证过期时间往后顺延；不传 `--group` 时可跨组列设备，但延长单设备时如果同一个 `device_id` 命中多个组，需要补 `--group` 消歧。

`collectDebug` 会按在线设备 `name` 定位目标节点，由 control 下发调试采集请求，节点把结构化 JSON snapshot 回传给 control，再由 `sdl-admin` 直接打印。当前实现是**同步等待返回**；成功后 control 会先把 snapshot 落盘，再把保存路径返回给 `sdl-admin`。当前支持的 section 包括：`runtime`、`gateway`、`peers`、`routes`、`nat`、`traffic`；不传 `--sections` 时默认采集全部。默认落盘目录为 `./data/debug-collect`，每个节点默认保留最近 `20` 份，同时更新同目录下的 `latest.json`。

`startDebugWatch` / `stopDebugWatch` 用于**异步调试观察**：control 按 `name` 启动一个限时 watch，会话期间 SDL 会把关键事件流持续回推到 control，control 将其追加写入该 watch 目录下的 `events.jsonl`。当前已接入的事件重点覆盖 Win10 dataplane 排查需要的路径：`gateway`（connect hello / auth result）、`icmp`（tun 出站、gateway/peer EchoReply 收包与回注）、`punch`（start / watchdog outcome）、`route`（direct route 失效触发 repunch）、`runtime`（watch started）。这条能力当前是**结构化事件流**，不是把客户端全部本地日志原样转发到 control。

Gateway 注册/保活分为两层：

- **HMAC 鉴权**：gateway 每次发送 `GatewayReportRequest` 都必须携带 `nonce + signature`。signature 覆盖 `GatewayReportProof`（`gateway_id + capabilities + report_unix_ms + nonce + gateway_channel` 的 protobuf 编码）；UDP channel 自身包含 `udp_public_key + udp_key_id`。control 使用 `gateway_ticket_secret` 做 HMAC-SHA256 校验，并对 `report_unix_ms + nonce` 执行新鲜度/重放保护。
- **管理批准**：鉴权通过后，除配置中的 `default_gateway_id` 对应 gateway 外，其他 gateway 仍需先经 `sdl-admin gateway --enlist <id>` 批准，其 `GatewayReportRequest` 才会返回成功。默认 gateway 的主机名固定要求为 `gateway.middlescale.net`。`sdl-admin gateway --list` 只显示已上报/已批准网关状态（含 `alive` 保活状态，默认网关若未上报不会单独合成一行）；`sdl-admin gateway --delist <id>` 可撤销已批准网关并触发客户端刷新。

control 对已批准网关采用租约保活（90 秒），并基于 `report_unix_ms + nonce` 做有限时间窗内的重放保护；超时未上报的网关不会继续被下发给客户端。

当前 gateway 下发模型是 channel-aware 的：

- `client -> gateway` 默认使用 UDP secure channel
- control 在 UDP `gateway_channel` 中下发 `udp_public_key` / `udp_key_id` 给客户端完成 UDP bootstrap
- 若 gateway 同时上报 QUIC channel，control 也会把对应的 `server_name` 和可选 CA PEM 一并下发，供客户端做 QUIC fallback

设备认证（auth device）由 `sdl auth` 发起：客户端输入 `--userId`、可选 `--group`（默认 `default.ms.net`）和 `ticket` 发送到 `sdl-control`，认证成功后设备才可注册入网。当前认证成功后的默认有效期为 30 天。

可选参数：

- `--socket <path>`：指定 socket 路径（也可用环境变量 `SDL_ADMIN_SOCKET`）。

## 验证

```bash
go test ./...
```

## 服务端镜像发布

仓库内置了 `release-image` workflow：

- tag push：发布 `ghcr.io/<owner>/sdl-control:<tag>`
- `workflow_dispatch`：可指定 `source_ref` 与 `release_tag`

这条 workflow 设计为给 `sdl-integration` 的 release gate 和 `sdl-deploy` 消费。

## 迁移方向（简要）

1. 继续补齐与 `vnts` 对齐的控制面协议行为（认证、注册、状态同步）。
2. 保持 control 与普通 HTTP API 共享同一个 HTTP/3 监听入口。
3. 将数据转发能力下沉到可集群化的 gateway 服务，实现控制面与转发面独立扩缩容。
