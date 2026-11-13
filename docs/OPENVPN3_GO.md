# 隧道引擎：内嵌 OpenVPN 3 Core 与 OpenVPN CLI 对比

网关用 Go 通过 C ABI（`go_backend/bridge.cpp`）内嵌官方 OpenVPN 3 Core：所有隧道在同一个进程里，每条隧道一个 Core 实例、一个 TUN。另一种做法是每条隧道起一个 `openvpn`（2.x）进程。本文记录两者在受控环境下的对比，用来决定引擎选型。

## 结论

继续用内嵌的 Core。

- **内存**：Core 明显更省。128 条隧道时 PSS 为 52.5 MiB 对 188.6 MiB；其中 13 MiB 是 Go 控制器本身，只算隧道的话约为 CLI 的 1/4.8。
- **进程**：Core 只有一个进程，隧道的建立、失败监控和回收都在进程内完成；CLI 方案要管理 N 个子进程和它们的输出。
- **停止**：Core 更快，128 条时最慢一条 270 ms，CLI 是 501 ms。
- **建连速度和 CPU**：两者相当。两轮测试里谁快谁慢互换了，差异主要来自受控服务端：它是单线程的 OpenVPN 2，要逐个处理握手，客户端引擎本身不是瓶颈。

## 测法

`.github/workflows/benchmark.yml`（手动触发）+ `scripts/benchmark.sh` + `go_backend/cmd/bench`，只在 GitHub Actions 上运行：

- 受控服务端是一个 OpenVPN 2.x，跑在独立的 network namespace 里，经 veth 连到宿主（`scripts/testbed.sh`）。客户端走真实的 UDP、TLS、证书加账号密码认证。
- 每个档位、每种引擎都用一个全新的服务端，两种引擎轮流先跑，避免上一轮残留的状态影响下一轮。
- 所有隧道同时建连。建好后通过每条隧道（套接字绑定到对应 TUN）请求服务端 namespace 里的 HTTP 端点，确认流量确实经过了隧道。
- 指标在所有隧道仍然在线、且已经发过流量之后采集：
  - 建连：从发起到引擎报告就绪（Core 收到 `CONNECTED`，CLI 输出 `Initialization Sequence Completed`）；
  - 全部就绪：从开始到最后一条隧道就绪的墙钟时间；
  - 停止：每条隧道的关闭耗时；
  - 内存：PSS 把共享页按使用它的进程数分摊，适合跨进程求和；RSS 会把共享库按进程数重复计算，只作参考；
  - CPU：每个线程 `schedstat` 里的运行时间（纳秒精度）。
- Core 一行统计的是整个 benchmark 进程，包括 Go 控制器；CLI 一行是所有 `openvpn` 子进程的合计。CLI 关闭了 DCO，两边都在用户态转发数据包。

## 结果

[Run 43373028169](https://github.com/LimLLL/vpngate-proxy/actions/runs/43373028169)：OpenVPN core 3.12（固定 commit `0b27d9df`）对 OpenVPN 2.6.19，ubuntu-24.04 runner。

| 隧道 | 引擎 | 全部就绪 ms | 中位 / 最慢建连 ms | 最慢停止 ms | 进程 | 线程 | PSS MiB | RSS MiB | CPU ms |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | core | 21 | 21 / 21 | 10 | 1 | 6 | 12 | 19 | 25 |
| 1 | cli | 17 | 17 / 17 | 12 | 1 | 1 | 2.6 | 9.4 | 10 |
| 16 | core | 233 | 210 / 230 | 64 | 1 | 23 | 19.1 | 26.1 | 215 |
| 16 | cli | 189 | 179 / 188 | 92 | 16 | 16 | 27.5 | 151.9 | 208 |
| 64 | core | 1136 | 884 / 1106 | 239 | 1 | 71 | 34.1 | 41.2 | 800 |
| 64 | cli | 909 | 697 / 834 | 250 | 64 | 64 | 97.3 | 608.1 | 842 |
| 128 | core | 2568 | 2010 / 2473 | 270 | 1 | 135 | 52.5 | 59.5 | 1656 |
| 128 | cli | 2296 | 1696 / 2176 | 501 | 128 | 128 | 188.6 | 1215.1 | 1808 |

每个档位的所有隧道都建连成功、都通过了流量验证、都正常停止。Go 控制器在建任何隧道之前占 13.1 MiB。

另一轮（[run 43372286207](https://github.com/LimLLL/vpngate-proxy/actions/runs/43372286207)，当时还没有 PSS，CPU 统计也有误）的建连结果是：64 条时 Core 1.4 s、CLI 2.7 s，128 条时 Core 1.8 s、CLI 3.0 s，正好和上表反过来，说明建连速度在两轮之间的波动比引擎之间的差别还大。

## 局限

- 只跑了两轮，共享 runner 的噪声没有平均掉。要下更细的结论，需要多跑几轮取分布。
- 受控服务端是单线程的 OpenVPN 2，高并发时建连时间主要反映服务端排队。
- 没有测吞吐和长时间运行；没有测公网 VPNGate 节点（它们的可用性波动远大于引擎差异）。
- 旧版本文档里"128 条 Core 50 MiB 对 CLI 1.2 GiB"用的是 RSS 求和，夸大了差距。

## 运行

```bash
gh workflow run benchmark.yml --repo LimLLL/vpngate-proxy -f tunnels=1,16,64,128
```

结果表在该次运行的 Summary 页，每档每引擎的 JSON 报告（含每条隧道的明细）在 artifact `engine-benchmark-<N>` 里。
