# vpngate-proxy

基于 VPNGate 公共节点的 HTTP / SOCKS5 代理网关。Go 负责节点获取、隧道池和代理；OpenVPN 协议、TLS 和 TUN 由嵌入的官方 OpenVPN 3 Core（C++，经 `go_backend/bridge.cpp` 的 C ABI 调用）执行。

## 目录

| 路径 | 内容 |
| --- | --- |
| `go_backend/core` | OpenVPN 3 Core 的 Go 封装与生命周期管理 |
| `go_backend/gateway` | 隧道池、session 粘滞/TTL、HTTP/SOCKS5 代理 |
| `go_backend/web` | 节点目录（抓取 VPNGate API、缓存、路由筛选）、配置存储、运行时维护 |
| `go_backend/nodes` | VPNGate CSV 与 profile 解析 |
| `go_backend/cmd/vpngate-proxy` | 主程序 |
| `go_backend/cmd/{bench,probe,candidate,testserver,testauth}` | 基准、真实节点探针与 CI 测试辅助程序 |
| `mirror/vpngate.csv` | 打包的离线节点快照（测试夹具，及 API 与本地缓存都不可用时的兜底） |

## 运行

需要 Linux、root 权限和 `/dev/net/tun`。

```bash
vpngate-proxy --data-dir ./vpngate_data --initialize        # 生成配置并输出代理凭据
vpngate-proxy --data-dir ./vpngate_data --print-credentials # 查看代理凭据
sudo vpngate-proxy --data-dir ./vpngate_data                # 启动
```

代理默认监听 `127.0.0.1:7928`，必须认证：用户名 `session-<ID>[-t-<分钟>]`，密码为配置中的密码或 `LOCAL_PROXY_PASS`。同一 `<ID>` 在 TTL 内复用同一条隧道，TTL 默认 30 分钟，范围 1–1440。

常用环境变量：`VPNGATE_DATA_DIR`、`LOCAL_PROXY_HOST`、`LOCAL_PROXY_PORT`、`LOCAL_PROXY_PASS`、`LOCAL_PROXY_MAX_CONNECTIONS`、`FETCH_INTERVAL_SECONDS`、`VPNGATE_API_HTTPS_URL`、`VPNGATE_API_HTTP_URL`、`VPNGATE_BUNDLED_SNAPSHOT`、`OPENVPN_UPSTREAM_SOCKS`、`OPENVPN_UPSTREAM_HTTP`。

## 测试

本地不编译、不测试；全部在 GitHub Actions（`.github/workflows/go-gateway.yml`）中执行：编译固定版本的 OpenVPN 3 Core，跑 Go 单测、vet，再在真实 TUN 上做受控 session 验证。手动触发并附带真实 VPNGate 出口验证：

```bash
gh workflow run go-gateway.yml --repo LimLLL/vpngate-proxy -f live=true
```

## 许可

GPL-3.0，见 `LICENSE`。
