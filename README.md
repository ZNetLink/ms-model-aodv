# ms-model-aodv

MANET 自组网 AODV 路由协议模型（妙算仿真）

本仓库实现了基于 AODV（Ad hoc On‑Demand Distance Vector）的按需路由协议进程模型，可在妙算仿真环境中为移动自组网（MANET）提供按需 IPv4 路由能力。模型通过 UDP 端口 654 发送/接收 AODV 控制报文，并与基础 IP 模型进行联动。

## 目录结构

- `model.json`：妙算模型元数据，声明进程模型、数据包格式等；
- `models/aodv.pr.m`：AODV 进程模型定义（状态机、属性等，仅描述层）；
- `models/aodv.pkt.m`：AODV 报文格式定义，包含：
  - `header`：指向 AODV 头部对象（`AodvHeader` 等）；
  - `data`：指向具体的 AODV 消息对象（RREQ/RREP/RERR/Hello）；
- `pycodes/aodv/`：Python 实现代码与打包配置；
  - `pycodes/aodv/src/aodv/__init__.py`：AODV 协议进程的完整实现；
  - `pycodes/aodv/pyproject.toml`：Python 包配置（依赖 `miaosuan`）。

## 依赖关系

本模型依赖以下组件（由妙算平台或基础模型提供）：

- `miaosuan` 仿真引擎；
- 基础 IP 模型：`miaosuan_models_basic.ip`；
- 基础 UDP 模型：`miaosuan_models_basic.udp`（AODV 控制报文通过 UDP 传输）。

在节点内部，推荐的连接方式为：

`应用业务` ↔ `IP` ↔ `UDP` ↔ `AODV`

AODV 模块与 UDP 模块通过一对输入/输出流直接相连，AODV 不参与业务数据转发，仅负责路由控制与 IP 路由表维护。

## AODV 进程模型概览

### 状态机

`models/aodv.pr.m` 对应的 Python 实现在 `AodvProcess` 中，状态机主要包括：

- `Register`：注册阶段
  - 记录自身模块与所在节点；
  - 将进程注册到节点进程表中（协议名为 `"aodv"`）；
  - 通过一个非常短的自中断等待 UDP 完成初始化。
- `Init`：初始化阶段
  - 读取模块属性 `Subnet`，解析为 IPv4 网段；
  - 在节点上查找 IP 模块及其内部数据（接口表等）；
  - 在该子网内确定本节点 IPv4 地址，并收集启用 AODV 的接口；
  - 初始化路由表、邻居表、RREQ 缓存等内部状态；
  - 建立与 UDP 模块的通信关系，并在 UDP 端口 654 上注册为应用。
- `Idle`：工作阶段
  - 响应自中断（定时器）、流中断（来自 UDP 的 AODV 报文）、远程中断（来自 IP 的按需路由请求）；
- `Disabled`：禁用状态
  - 若在指定子网内未找到启用 AODV 的接口，则进入该状态，保持空转。

### 模块属性：Subnet

在 `models/aodv.pr.m` 中，AODV 模块定义了一个可配置属性：

- `Subnet`（字符串，默认 `"192.168.1.0/24"`）  
  指定 AODV 管理的 IPv4 子网。

在运行时，AODV 会：

- 在本节点的 IP 接口表中查找位于该子网内的接口，并将其中一个接口地址作为本节点 AODV 地址；
- 在所有接口上检查是否启用了 AODV（`interface.routing_protocols` 中包含 `"AODV"`），将这些接口加入 `enabled_intfs`，用于后续广播 Hello、RREQ、RERR 等控制报文。

若在 `Subnet` 指定的范围内找不到本节点地址，将直接抛出错误；若没有任何接口启用 AODV，则初始化完成后进入 `Disabled` 状态。

## 与 IP/UDP 模型的交互

### 与 IP 模型

AODV 通过基础 IP 模型提供的接口进行路由协同：

- 启动时调用 `on_demand_routing_protocol_register`，将自己注册为某子网的“按需路由协议”；
- 通过 `add_route_entry` / `remove_route_entry` 在 IP 的 RIB 中增删路由，路由来源标识为 `"aodv"`；
- 当 IP 无现成路由且需要按需路由时，通过远程中断通知 AODV：
  - AODV 收到 `ON_DEMAND_NOTIFY_TYPE_NEED` 类型的通知后，发起路由发现（RREQ）；
  - 路径建立成功后，通过 `ip_on_demand_routing_notify`（类型 `ON_DEMAND_NOTIFY_TYPE_FOUND`）回告 IP 层，IP 随后即可使用新路由。

路由表条目结构大致为：

- 目标前缀：`/32` 单主机路由；
- 跳数（hop count）作为度量值（metric）；
- 下一跳地址及出接口；
- 行政距离使用 `ADMIN_DIST_AODV`。

### 与 UDP 模型

AODV 所有控制报文均通过 UDP 端口 `654` 发送，数据平面业务流量仍由 IP/UDP 及上层应用处理。

初始化流程如下：

1. 通过 `ms.get_out_streams()` / `ms.get_in_streams()` 获取与 UDP 相连的流；
2. 使用 `pr_discover` 校验相连模块的进程属性，确保确实为 UDP 模块；
3. 使用远程中断向 UDP 发送 `udp_command` ICI：
   - `command = "listen"`；
   - `app module id = AODV 模块 ID`；
   - `local port = 654`；
4. 之后 UDP 会将目的端口为 654 的报文提交给 AODV，ICI 类型为 `udp_ind`，其中至少包含：
   - `remote address`：对端地址（整数形式）；
   - `remote port`：对端端口；
   - `in intf idx`：入接口索引。

收到来自 UDP 的报文后，AODV 会：

- 校验源端口是否为 654，否则丢弃；
- 将 `remote address` 转换为 IPv4 地址；
- 解析 `aodv` 报文格式中的 `header` 与 `data` 字段，并根据消息类型分发到对应处理函数。

发送报文时，AODV 会创建 `udp_ind` ICI，设置远端地址、端口和本地端口（654），再通过与 UDP 相连的输出流发送。

## 协议行为与内部数据结构

### 主要数据结构

在 `pycodes/aodv/src/aodv/__init__.py` 中定义了若干核心数据结构：

- `RouteEntry`：路由表条目，包含目的地址、目的序列号、跳数、下一跳、出接口、生命周期、路由状态等；
- `NeighborEntry`：邻居表条目，保存邻居地址、最近一次收到 Hello 的时间、Hello 序列号、链路状态等；
- `RreqMessage` / `RrepMessage` / `RerrMessage` / `HelloMessage`：对应 AODV 标准中的四类控制消息；
- `RreqCacheEntry`：RREQ 缓存，避免重复处理同一（源，RREQ ID）组合。

数据包格式 `models/aodv.pkt.m` 中的 `header` / `data` 字段分别指向这些 Python 对象。

### 路由发现（RREQ/RREP）

在 IP 请求按需路由或已有路由失效时，AODV 会调用 `initiate_route_discovery`：

- 若路由表中已经存在有效路由且未超时，直接通知 IP “已找到”；
- 否则：
  - 增加本端序列号；
  - 构造 `RreqMessage`，包含目标地址、本端地址及序列号等；
  - 若已有目标的有效序列号，则填入；否则设置 `AODV_FLAG_UNKNOWN_SEQ_NUM` 标志；
  - 为 RREQ 分配新的 `rreq_id`，并通过 `broadcast_rreq` 在所有启用 AODV 的接口上广播。

其他节点收到 RREQ 后会：

- 使用 `RreqCacheEntry` 过滤重复 RREQ；
- 更新到原始发起者（originator）的反向路由；
- 若自己即为目标，或已有更“新”的到目标的有效路由，则生成 RREP：
  - 若为目标节点，则根据当前序列号构造新的 RREP；
  - 若使用已有路由回复，则沿用路由中的跳数、序列号和剩余生命周期；
- 将 RREP 通过 UDP 单播返回至上一跳。

收到 RREP 的中间节点会更新到目标的正向路由，并按 AODV 规则继续转发，直至到达原始发起者。

### 邻居维护与 Hello 消息

AODV 周期性发送 Hello 报文用于邻居探测和链路维护：

- 定时器周期由 `hello_interval` 控制（默认 1s，内部常量）；
- 发送 Hello 时，增加本端序列号，并在 `HelloMessage` 中携带生命周期 `life_time`（默认与活动路由超时相关）。

收到 Hello 后：

- 若邻居已存在于邻居表，更新其最近收到时间与序列号；
- 若为新邻居，创建对应 `NeighborEntry`，并为其建立一条跳数为 1 的路由。

清理定时器（`cleanup_interval`，默认 30s）负责：

- 移除已过期的路由（生存时间超时），并从 IP 路由表中删除；
- 若邻居超过 `allowed_hello_loss * hello_interval` 时间无 Hello，则判定为失效，删除邻居并触发相关路由失效；
- 清除过期的 RREQ 缓存项。

### 路由错误（RERR）

当检测到经由某邻居的路由失效（例如邻居超时）时，AODV 会：

- 将相关路由状态标记为无效，并从 IP 路由表中移除；
- 根据失效目的集合构造 `RerrMessage`，在启用 AODV 的接口上广播；
- 其他节点收到 RERR 后会沿着前向路径传播失效信息，联动清理自身的相关路由。

## 默认参数与限制

当前实现中，若干 AODV 参数以常量形式内建（暂未暴露为可配置属性），包括但不限于：

- `DEFAULT_ACTIVE_ROUTE_TIMEOUT = 3.0` 秒；
- `DEFAULT_HELLO_INTERVAL = 1.0` 秒；
- `DEFAULT_ALLOWED_HELLO_LOSS = 2`；
- `DEFAULT_RREQ_RETRIES = 2`；
- `DEFAULT_NET_DIAMETER = 35` 等。

其他注意事项：

- 仅支持 IPv4 地址（使用 `ipaddress.IPv4Address`）；
- AODV 控制报文统一使用 UDP 端口 `654`；请避免在同一节点上将该端口分配给其他应用；
- AODV 模块假定其与 UDP 模块之间存在唯一的一对流连接，并作为唯一的 AODV 进程注册到节点上。

## 在仿真中的使用建议

- 在需要 AODV 的节点上：
  1. 放置 IP 模块、UDP 模块以及 AODV 模块，并按 `IP ↔ UDP ↔ AODV` 方式连线；
  2. 在 IP 接口配置中，为需要运行 AODV 的接口启用 AODV（`routing_protocols` 包含 `"AODV"`）；
  3. 在 AODV 模块属性中，将 `Subnet` 设置为覆盖该节点 IP 地址的网段；
  4. 使用妙算提供的业务流模型（如 UDP/TCP 应用）产生数据流，依赖 IP 的按需路由机制触发 AODV 路由发现。

- 若需要二次开发或调试：
  - 可以直接阅读 `pycodes/aodv/src/aodv/__init__.py`，其中对每个步骤都附有日志输出（使用 `logging` 标准库），便于在仿真中追踪路由发现、邻居更新和路由错误传播过程。

