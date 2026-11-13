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

## 运行

需要 Linux、root 和 `/dev/net/tun`。

```bash
vpngate-proxy --data-dir ./vpngate_data --print-credentials  # 首次运行生成 config.json，并打印账号密码
sudo vpngate-proxy --data-dir ./vpngate_data
```

数据目录：

- `config.json`：账号、密码、监听地址、隧道数量（`max_tunnels`，默认 64）、预热隧道数（`min_idle_tunnels`，默认 4）、节点淘汰阈值（`node_max_age_days` 7、`node_max_failures` 5）、VPNGate API 地址。
- `nodes.json`：累计的节点表。每 20 分钟拉一次 API，按 IP 去重合并；节点超过 `node_max_age_days` 没出现在列表里，或连续连接失败 `node_max_failures` 次，就被淘汰。

环境变量 `LOCAL_PROXY_USER`、`LOCAL_PROXY_PASS`、`LOCAL_PROXY_HOST`、`LOCAL_PROXY_PORT` 覆盖配置但不写回文件；对外服务设 `LOCAL_PROXY_HOST=0.0.0.0`。拉取节点列表遵循 `HTTPS_PROXY` / `HTTP_PROXY`。

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
