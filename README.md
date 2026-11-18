# syncd — 一个把特权收进最小助手进程的同步服务（Rust）

这是同一个 Mac 同步服务的两个版本：

* `syncd-monolith` —— **拆分前**：单进程，以 root 常驻，解析网络数据和
  挂载磁盘在同一个地址空间。
* `syncd-agent` + `syncd-helper` —— **拆分后**：低权限主进程负责所有解析和
  文件处理；一个很小的、以 root 运行的助手只做四件事，两者之间只有一条
  定长 64 字节帧的 Unix socket。

目标不是"把代码写得更安全"，而是让大量不可信的解析代码**不持有特权**：
即使被完全攻破，攻击者拿到的也只是用户权限。

* 设计理由（接口为什么这么划）：[docs/design.md](docs/design.md)
* 拆分前后可被滥用的操作对比：[docs/comparison.md](docs/comparison.md)

## 依赖

零第三方依赖。`cargo tree` 的结果是空的——每个 crate 只用 `std` 和
macOS 系统框架（Security / CoreFoundation，经手写 FFI）。特权进程和它共享
的协议层尤其如此，这是刻意的：可审计面越小越好。

需要 macOS 做集成测试（审计令牌、代码签名）。单元测试跨平台。

## 快速开始

```bash
cargo test --workspace        # 48 个单元测试
./scripts/test-integration.sh # 6 个集成测试（真实助手进程）
./scripts/demo.sh             # 拆分前后并排演示 + 攻击矩阵
```

`scripts/demo.sh` 会：启动单进程版，展示它如何在同一进程里处理请求；启动
拆分版，展示白名单内外的不同结果；展示一个不在白名单里的进程（python3）被
助手在策略之前拒绝；最后打印完整攻击矩阵。

## crates

| crate | 作用 | 权限 |
|---|---|---|
| `protocol`（`sync-wire`） | 整个信任边界。定长帧、无字符串、闭合操作集 | 共享，无 `unsafe` |
| `sync-core` | 主进程和单体共用的解析/文件/卷表逻辑，以及 `PrivOps` 抽象 | 无特权 |
| `agent`（`syncd-agent`） | 低权限主进程。拒绝以 root 启动 | 用户 |
| `helper`（`syncd-helper`） | 小特权进程。每帧校验来源 + 自己的策略 | root |
| `monolith`（`syncd-monolith`） | 拆分前的单进程版本，作对照 | root |
| `redteam` | 攻击场景、探针、集成测试 | 测试 |

两版共用 `dispatch` 和 `sync-core` 的解析逻辑，所以对比是"同样的代码、
不同权限"，不是"两个不同的程序"。

## 接口一览

请求 64 字节 / 回复 32 字节，Unix socket，一连接一请求。

| 操作 | 参数 | 说明 |
|---|---|---|
| `Health` | 无 | 健康检查，无特权动作 |
| `MountVolume` | 16 字节 UUID | 助手用自己的表把 UUID 映射到路径 |
| `UnmountVolume` | 16 字节 UUID | 同上 |
| `SetSystemSetting` | 设置 id + 0/1 | 仅三项设置 |

请求里**没有路径、没有命令、没有字符串**。被攻破的主进程只能从助手的
白名单里指认对象，不能定义对象。

## 助手的来源校验

每读到一帧，助手重新解析对端**当前**镜像的代码哈希，对照白名单。为什么必须
每帧做、为什么不能按 pid——见 [design.md 第 4 节](docs/design.md#4-助手如何校验来源)，
那里有 macOS 上的实测结论。

## 已知限制

演示里的挂载/卸载是模拟的；真实部署需要接 `diskutil` 并用签名权利、
designated requirement（而非裸哈希）做校验、以及一个 root 拥有的
socket 目录。完整清单在 [design.md 第 7 节](docs/design.md#7-这个设计没有解决的问题务必读)。
