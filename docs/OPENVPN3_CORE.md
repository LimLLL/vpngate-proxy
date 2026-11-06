# OpenVPN 3 Core C++ 实验后端

`openvpn3_backend/` 验证的是：Python 直接调用 OpenVPN 官方仓库自带的 SWIG Python 绑定，再由 C++ Core 完成 profile 解析、TLS、加密和连接回调。它不是 Python 重写的 OpenVPN，也暂时不改变 `vpngate_manager.py` 默认使用 OpenVPN 2.x CLI 的路径。

## 实现内容

- 固定 OpenVPN 3 Core 源码 commit，避免上游变化破坏可复现性。
- 使用官方 `client/ovpncli.i` 和 CMake `ovpnclilib` target 生成扩展。
- `core.py` 调用 `ClientAPI_OpenVPNClientHelper` 和 `ClientAPI_OpenVPNClient`。当前 pin 版本的 `crypto_self_test()` 在 OpenSSL 构建下是上游明确的空操作，不据此宣称加密自检已通过。
- SWIG director 把 C++ 的 `event()`、`log()` 等调用转回 Python。
- 默认追加 `route-nopull`，防止实验连接改写宿主机默认路由。
- `live_vpngate.py` 在独立 GitHub runner 上连接真实节点，再复用项目现有 SOCKS5 代理检查出口 IP。

## 为什么只通过 GitHub Actions 验证

本机为 macOS，而目标运行环境是 Linux TUN。所有编译和测试都在 `ubuntu-24.04` runner 上执行，不需要也不应在本机运行构建命令。

基础构建与测试随相关 push 自动运行：

```bash
gh run list --repo LimLLL/vpngate-proxy --workflow openvpn3-core.yml
gh run watch --repo LimLLL/vpngate-proxy
```

真实 VPNGate 网络测试只手动触发，避免第三方节点波动影响日常构建：

```bash
gh workflow run openvpn3-core.yml --repo LimLLL/vpngate-proxy -f live_test=true
gh run list --repo LimLLL/vpngate-proxy --workflow openvpn3-core.yml --limit 1
gh run watch --repo LimLLL/vpngate-proxy
```

失败后读取完整日志：

```bash
gh run view --repo LimLLL/vpngate-proxy --log
```

## 当前边界

这是接入验证原型，还不是多 session 代理池。Python/SWIG 在真实节点收到 C++ `CONNECTED` 后仍发生控制线程调度阻塞，未通过真实连接验证。已成功跑通真实隧道、代理出口和停止路径的是独立 Go 控制器方案，见 `docs/OPENVPN3_GO.md`。当前仍未实现：

- 一个 Python 进程中的多 TUN 生命周期管理；
- `session-xxx-t-minutes` 解析与粘滞映射；
- 隧道预热、容量限制和空闲回收；
- 替换生产管理器的 OpenVPN 2.x 后端。

OpenVPN 3 Core 与 2.x 协议兼容，但免费节点可用性和具体配置指令仍需实测。网络测试成功才能证明当前绑定路径可建立隧道并承载代理流量，不能据此承诺切换速度或 VPNGate 节点可用时长。
