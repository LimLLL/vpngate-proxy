# vpngate-proxy

把 VPNGate 公共节点包装成类似商业动态住宅代理的 HTTP / SOCKS5 网关：用户名里带国家和会话参数，控制出口国家与 IP 粘滞时长。Go 负责节点、隧道池和代理；OpenVPN 协议、TLS 和 TUN 由嵌入的官方 OpenVPN 3 Core（C++，经 `go_backend/bridge.cpp` 的 C ABI 调用）执行。需求见 [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)。

## 用法

```
http://<账号>[-country-<国家>][-session-<会话ID>[-t-<分钟>]]:<密码>@<主机>:7928
socks5://同上
```

| 用户名 | 行为 |
| --- | --- |
| `user` | 每个新连接轮换出口 |
| `user-session-abc-t-10` | 同一出口 IP 粘滞 10 分钟（默认 30），到期换到实测出口不同的隧道 |
| `user-country-jp-session-abc` | 日本节点，粘滞 30 分钟 |

## 部署（Docker）

需要一台 Linux 服务器（x86_64 或 arm64，镜像两种架构都有），装好 Docker 和 Docker Compose 插件，内核提供 `/dev/net/tun`（绝大多数 VPS 默认就有，没有的话先在服务商面板里开启 TUN/TAP）。

**1. 准备目录和 compose 文件。** 镜像 `ghcr.io/limlll/vpngate-proxy` 是公开的，不需要登录：

```bash
mkdir -p /opt/vpngate-proxy && cd /opt/vpngate-proxy
curl -fsSLO https://raw.githubusercontent.com/LimLLL/vpngate-proxy/main/compose.yaml
```

默认把代理端口 7928 映射到宿主所有网卡；只想本机使用就把 `ports` 改成 `"127.0.0.1:7928:7928"`。

**2. 启动并查看账号密码。** 首次启动会在 `./data/config.json` 生成随机账号和密码：

```bash
docker compose up -d
docker compose exec vpngate-proxy vpngate-proxy --print-credentials
docker compose logs -f   # 看节点拉取和隧道建立情况
```

**3. 使用。** 把 `<服务器IP>`、账号、密码代入：

```bash
curl -x "http://<账号>:<密码>@<服务器IP>:7928" https://api.ipify.org                      # 每次换出口
curl -x "http://<账号>-session-abc-t-10:<密码>@<服务器IP>:7928" https://api.ipify.org     # 10 分钟内固定出口
curl -x "socks5h://<账号>-country-jp:<密码>@<服务器IP>:7928" https://api.ipify.org       # 只用日本节点
```

**更新与维护**

- 升级：`docker compose pull && docker compose up -d`。`latest` 跟随 main 上测试通过的最新提交；也可以把镜像标签改成固定的 `sha-<提交前7位>` 或版本号。
- 改账号、密码、隧道数量：编辑 `./data/config.json` 后 `docker compose restart`；或者在 `compose.yaml` 里用 `LOCAL_PROXY_USER` / `LOCAL_PROXY_PASS` 覆盖。
- `./data/nodes.json` 是累计的节点表，删掉后会从下一次 VPNGate 列表重新积累。
- 服务器访问不了 `www.vpngate.net` 时，在 `compose.yaml` 的 `environment` 里加 `HTTPS_PROXY`（只用于拉节点列表）。

容器需要 `NET_ADMIN` 和 `/dev/net/tun`；隧道、策略路由和 `rp_filter` 都在容器自己的网络命名空间里，不改宿主路由。镜像由 `.github/workflows/docker.yml` 在 "Go native gateway" 测试通过后，分别在 x86_64 和 arm64 原生 runner 上构建，合并成多架构镜像推送到 `ghcr.io/limlll/vpngate-proxy`；推 `v*` 标签会额外发布对应版本号。

### 配置

`./data/config.json`：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `username` / `password` | 随机生成 | 代理账号与密码 |
| `proxy_host` / `proxy_port` | `127.0.0.1` / `7928` | 监听地址；镜像里由 `LOCAL_PROXY_HOST=0.0.0.0` 覆盖 |
| `max_tunnels` | 64 | 同时存在的隧道上限 |
| `min_idle_tunnels` | 4 | 保持预热、没有会话占用的隧道数 |
| `node_max_age_days` / `node_max_failures` | 7 / 5 | 节点超过这么多天没出现在列表里、或连续失败这么多次就淘汰 |
| `tun_base` | 0 | TUN 设备编号起点（`tun<tun_base+n>`） |
| `api_urls` | VPNGate API 的 HTTPS 与 HTTP 地址 | 节点列表来源，按顺序尝试 |

环境变量 `LOCAL_PROXY_USER`、`LOCAL_PROXY_PASS`、`LOCAL_PROXY_HOST`、`LOCAL_PROXY_PORT` 覆盖配置但不写回文件。

### 不用 Docker

需要 Linux、root 和 `/dev/net/tun`，自行按 `Dockerfile` 编译 OpenVPN 3 Core bridge 与 Go 程序后：

```bash
vpngate-proxy --data-dir ./vpngate_data --print-credentials
sudo vpngate-proxy --data-dir ./vpngate_data
```

## 目录

| 路径 | 内容 |
| --- | --- |
| `go_backend/core` | OpenVPN 3 Core 的 Go 封装 |
| `go_backend/gateway` | 用户名解析、隧道池（每节点一条隧道、按实测出口 IP 分配与轮换、会话粘滞/TTL、预热与回收）、HTTP/SOCKS5 代理 |
| `go_backend/nodes` | VPNGate CSV 与 profile 校验、累计节点表、API 拉取 |
| `go_backend/cmd/vpngate-proxy` | 主程序与配置 |
| `go_backend/cmd/{bench,probe,candidate,testserver,testauth}` | 基准、真实节点探针与 CI 测试辅助程序 |

## 测试

本地不编译、不测试；全部在 GitHub Actions 中执行。`go-gateway.yml` 编译固定版本的 OpenVPN 3 Core，跑 Go 单测和 vet，再在受控 OpenVPN 服务端上用真实 TUN 验证粘滞、TTL 换节点和长连接存活。`live=true` 时再启动真实代理连 VPNGate 节点，检查轮换、粘滞、会话间换 IP 和 TTL 换 IP：

```bash
gh workflow run go-gateway.yml --repo LimLLL/vpngate-proxy -f live=true
gh workflow run benchmark.yml --repo LimLLL/vpngate-proxy -f tunnels=1,16,64,128   # Core 与 openvpn CLI 对比
```

`benchmark.yml` 的结果表在该次运行的 Summary 页，JSON 报告在 artifact 里。

## 许可

GPL-3.0，见 `LICENSE`。
