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

## 边界

当前是连接与生命周期验证，不是多 session 代理产品。只有在实际日志中观察到 `CONNECTED`、代理公网访问以及 clean stop，才能认为 Go/C++ 路径具备替代实验 CLI 后端的基本条件。测得的成功时间包括远端网络 RTT、TLS 与认证，不能仅归功于语言切换。
