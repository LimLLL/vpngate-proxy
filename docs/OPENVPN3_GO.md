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

这只是同一节点的一次测量，不是统计意义上的性能结论。Python/SWIG 实验在收到原生 `CONNECTED` 后未能恢复 Python 控制线程，当前保留为实验代码，不作为生产后端。Go 的独立链路已经验证成功，本机没有执行构建或测试。

## 并发与开销基准

`openvpn3-benchmark.yml` 使用同一节点的相同 profile，在一个 Go 进程中嵌入 N 个 C++ Core 实例，与 N 个 OpenVPN 2.x CLI 进程对比。每个接口独立执行策略路由、绑定网卡的公网访问与出口 IP 检查。

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

CLI 指标来自实际 OpenVPN 子进程 PID，而非 Python 编排器；其 CLI 连接计时仍包含 `--route-delay 2`。RSS/峰值对于多个 CLI 进程采用累加，可能重复计入共享库页，不等于独占物理 RAM 增量。Go 指标包含单个 Go 控制器及所有嵌入式 C++ Core。协议握手和节点波动均会计入耗时，不能仅凭一轮对比推断 Go/CLI 的稳定提速比例。

## 边界

当前是连接、生命周期及独立并发基准，不是多 session 代理产品，也尚未替换 `vpngate_manager.py` 的默认 CLI 后端。生产化还需要多隧道分配、session 粘滞、TTL、预热池以及空闲回收。VPNGate 节点不稳定时，失败样本不能被当作成功性能数据。
