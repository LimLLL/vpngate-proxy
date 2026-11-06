# Go 调用官方 OpenVPN 3 Core 的验证链路

## 目的

验证 Python/SWIG 路线遇到的 `CONNECTED` 后调度问题是否仅限其绑定方式，同时保留生产项目原有 OpenVPN 2.x CLI 和 Python 代理。无第三方 Go 绑定被复制或引入为项目依赖，现有 AGPL Go 项目只作研究参考，不纳入分发。

## 组成

- `go_backend/bridge.cpp`：很薄的 C ABI 层，直接包含官方 `client/ovpncli.cpp`。
- `go_backend/core/`：Go 对象、整数 ID 回调注册表、goroutine 和生命周期管理。
- `go_backend/cmd/probe/`：真实连接、读取连接信息、保持连接、显式停止的探针。
- `proxy_smoke.py`：Go 创建 TUN 后，通过原有 SOCKS5 代理访问公网。

OpenVPN 协议、TLS、凭据、加解密和 TUN 始终由官方 C++ Core 执行，不是 Go 模拟协议，也不是 `exec("openvpn")`。

`connect()` 仍在专用 goroutine 中运行。C++ 回调只复制字符串并将事件交给 Go，未在其中再次调用 OpenVPN API。控制 goroutine 在收到 `CONNECTED` 后读取详情并决定后续动作。

## 只通过 GitHub Actions 执行

本地（macOS）不进行编译、真实 TUN 或测试。相关 push 会编译并跑基础 Go 测试；需要真实 VPNGate 节点时：

```bash
gh workflow run openvpn3-go.yml --repo LimLLL/vpngate-proxy -f live_test=true
gh run list --repo LimLLL/vpngate-proxy --workflow openvpn3-go.yml --limit 1
gh run watch --repo LimLLL/vpngate-proxy
```

所有外网测试由 Ubuntu 24.04 runner 执行，OpenVPN Core 使用固定 commit `0b27d9df493db8bc9dc459a2b1cb6b67037742b2`。每轮会保存相同快照供 Go/C++ 与 OpenVPN 2.x CLI 对照，减少使用不同候选造成的误导。

## 已验证的真实连接

GitHub Actions run `42195536699` 对同一个 VPNGate 节点完成了 Go/C++ Core 与 CLI 的顺序对照：

- Go/C++ Core 在 `tun0` 收到 `CONNECTED`，连接计时 `1355 ms`；
- `stop_ms=8` 正常退出，TLS、认证以及失败连接后的资源清理测试均通过；
- Go/C++ 建立的隧道通过项目已有 SOCKS5 代理访问公网，返回节点出口 IP；
- 相同 profile 的 OpenVPN 2.x CLI 也成功建立隧道与代理流量，计时 `3565 ms`，其中包含适配器设置的 `--route-delay 2`。

这只是同一节点的一次测量，不是统计意义上的性能结论；该 CLI 计时还包含当时的固定等待。当前 OpenVPN 2 对照命令已改用 `--route-delay 0`。Python/SWIG 实验在收到原生 `CONNECTED` 后未能恢复 Python 控制线程，当前保留为实验代码，不作为生产后端。Go 的独立链路已经验证成功，本机没有执行构建或测试。

## 并发与开销基准

`openvpn3-benchmark.yml` 使用仅存在于本次 Action job 的受控 OpenVPN 服务端，隔离公网节点的可达性和匿名认证波动。服务端与 HTTP 验证点运行在独立的 Linux network namespace；客户端在主网络命名空间分别通过真实 TLS、PKI 证书、账号密码认证和 UDP 隧道连接。客户端到虚拟 HTTP 地址的流量必须穿过它自己的 TUN，不能直接命中主机的 local 路由。

测试使用不同客户端证书和独立的 `tunN`。每个 case 使用全新服务端，避免 OpenVPN 2.x 收到 Core 退出消息后等待约五秒确认 ACK 时，将旧客户端残留状态带入下一轮。每个 case 也使用独立日志目录；PKI、账号检查脚本、namespace 和 veth 均由测试自动创建、清理，不在用户 Mac 上运行。

此前的公网配对测试同时观察到了单隧道成功及同一节点偶发 `AUTH_FAILED`。SoftEther 的服务端可以限制同一用户的并发登录数，但客户端无法据此断定具体志愿者节点的拒绝原因；因此公网可用性保留在 `openvpn3-go.yml`，性能基准改用上述受控环境。

```bash
gh workflow run openvpn3-benchmark.yml --repo LimLLL/vpngate-proxy -f concurrency=all
gh run list --repo LimLLL/vpngate-proxy --workflow openvpn3-benchmark.yml --limit 1
gh run watch --repo LimLLL/vpngate-proxy
```

`concurrency` 可选 `1`、`2`、`4` 或 `all`。每个 case 的 `final.json`、Go 原生日志及统一 `comparison.json` 会上传为 Actions artifact。

测量包括：

- 每个 session 的配置时间与连接计时；全部就绪的 wall time 和最慢隧道的计时；
- 每条隧道的停止时间；
- 引擎进程数（Go 始终为 1，CLI 为隧道数）及连接后线程数；
- 活跃 RSS、生命周期峰值 RSS；
- 流量检查到停止前的引擎 CPU 累计时间。

CLI 指标来自实际 OpenVPN 子进程 PID，而非 Python 编排器；两种后端都测量到其就绪事件，CLI 使用 `--route-delay 0`，不额外计入固定等待。RSS/峰值对于多个 CLI 进程累加，可能重复计入共享库页，不等于独占物理 RAM 增量。Go 指标包含 Go 控制器与所有嵌入式 C++ Core，服务端和 HTTP 服务不计入。本基准不测量公网 RTT、持续吞吐或志愿者节点的服务端开销，不能用一轮数据推断稳定提速比例。

## 已验证的并发结果

[GitHub Actions run 42243782997, attempt 2](https://github.com/LimLLL/vpngate-proxy/actions/runs/42243782997) 最终状态 `completed / success`，六个 case 均通过，所有隧道逐个完成真实 HTTP 请求，错误与清理错误列表为空：

| 并发数 | Go + C++ Core 最慢隧道 / 就绪壁钟 | CLI 最慢隧道 / 就绪壁钟 | Go / CLI 活跃 RSS | Go / CLI 进程数 | Go / CLI 线程数 |
| --- | --- | --- | --- | --- | --- |
| 1 | 42.8 / 45.9 ms | 49.0 / 52.7 ms | 14.2 / 9.5 MiB | 1 / 1 | 6 / 1 |
| 2 | 88.3 / 92.8 ms | 90.1 / 91.6 ms | 14.7 / 18.8 MiB | 1 / 2 | 7 / 2 |
| 4 | 154.1 / 161.3 ms | 184.5 / 186.8 ms | 15.4 / 38.1 MiB | 1 / 4 | 9 / 4 |

每路 Go 停止约 9.6 至 17.4 ms；该成功报告见 `openvpn3-benchmark-all-10/comparison.json` 及各 case `final.json`。实际 benchmark 使用真实 UDP、TLS、certificate + username/password 认证和独立 TUN，不模拟握手。

重要限制：每个 case 创建独立受控服务端、PKI 与 namespace，并用 N 个不同传输地址避免当前测试里观察到的 OpenVPN 2.6 UDP 分路行为污染数据；常规公网隧道端口并不天然采用相同拓扑。已跑通的度量只对这些真实协议 testbed 负责，不模拟 VPNGate 的速度或负载，也不推断发布性能指标。Go 测得的是单进程多引擎的进程、线程和生命周期收益，协议与加密仍由官方 C++ Core 执行。它没有实现 session 粘滞、TTL 或隧道预热，因此不能仅凭这组数字选型为正式 session-xxx-t-TTL 商业代理。

## 边界

当前是连接、生命周期及独立并发基准，不是多 session 代理产品，也尚未替换 `vpngate_manager.py` 的默认 CLI 后端。生产化还需要多隧道分配、session 粘滞、TTL、预热池以及空闲回收。VPNGate 节点不稳定时，失败样本不能被当作成功性能数据。
