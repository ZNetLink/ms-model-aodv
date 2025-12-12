import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import miaosuan as ms
from miaosuan.engine.engine import INTRPT_TYPE_REMOTE, INTRPT_TYPE_SELF, INTRPT_TYPE_STRM, Stream
from miaosuan.engine.simobj import SimObj
from miaosuan.mms.process_registry import (
    AttrType,
    ProcessAttribute,
    pr_attr_get,
    pr_attr_set,
    pr_discover,
    pr_register,
)

from ipv4.ip_support import (
    Interface,
    ModuleData,
    RIBEntry,
    addr_to_uint32,
    find_node_ip_module,
    find_node_ip_module_data,
    uint32_to_addr,
    LIMITED_BROADCAST_ADDR,
    ON_DEMAND_NOTIFY_TYPE_FOUND,
    ON_DEMAND_NOTIFY_TYPE_NEED,
    ON_DEMAND_NOTIFY_TYPE_FAILED,
)

from ipv4.routing import (
    ADMIN_DIST_AODV,
    add_route_entry,
    get_routing_entries_for_dest,
    on_demand_routing_protocol_register,
    remove_route_entry,
)

try:
    from ipv4 import REMOTE_INTRPT_CODE_ON_DEMAND_NOTIFY
except Exception:  # pragma: no cover - fallback if IP module is unavailable
    REMOTE_INTRPT_CODE_ON_DEMAND_NOTIFY = 1

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AODV协议常量
# ---------------------------------------------------------------------------

AODV_PORT = 654  # AODV标准端口号
AODV_PACKET_FORMAT = "aodv"

# AODV消息类型
AODV_MSG_TYPE_RREQ = 1  # 路由请求
AODV_MSG_TYPE_RREP = 2  # 路由回复
AODV_MSG_TYPE_RERR = 3  # 路由错误
AODV_MSG_TYPE_HELLO = 4  # Hello消息

# AODV标志位
AODV_FLAG_REPAIR = 0x01  # R标志：修复标志
AODV_FLAG_GRATUITOUS = 0x02  # G标志：感谢标志
AODV_FLAG_DEST_ONLY = 0x04  # D标志：仅目标回复
AODV_FLAG_UNKNOWN_SEQ_NUM = 0x08  # U标志：未知序列号

# 路由状态
ROUTE_STATE_VALID = 1  # 有效路由
ROUTE_STATE_INVALID = 2  # 无效路由
ROUTE_STATE_REPAIRING = 3  # 修复中

# 默认参数
DEFAULT_ACTIVE_ROUTE_TIMEOUT = 3.0  # 单位：秒
DEFAULT_HELLO_INTERVAL = 1.0  # 单位：秒
DEFAULT_ALLOWED_HELLO_LOSS = 2
DEFAULT_RREQ_RETRIES = 2
DEFAULT_CLEANUP_INTERVAL = 30.0  # 单位：秒
DEFAULT_RREQ_RATE_LIMIT = 10
DEFAULT_TIMEOUT_BUFFER = 2
DEFAULT_TTL_START = 1
DEFAULT_TTL_INCREMENT = 2
DEFAULT_TTL_THRESHOLD = 7
DEFAULT_LOCAL_ADD_TTL = 2
DEFAULT_NET_DIAMETER = 35
DEFAULT_NODE_TRAVERSAL_TIME = 0.040  # 单位：秒
DEFAULT_NET_TRAVERSAL_TIME = 2 * DEFAULT_NODE_TRAVERSAL_TIME * DEFAULT_NET_DIAMETER
DEFAULT_BLACKLIST_TIMEOUT = DEFAULT_RREQ_RETRIES * DEFAULT_NET_TRAVERSAL_TIME
DEFAULT_MAX_REPAIR_TTL = 32

ROUTE_SOURCE_AODV = "aodv"

# 自中断代码
INTRPT_CODE_HELLO_TIMER = 1
INTRPT_CODE_CLEANUP_TIMER = 2


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RouteEntry:
    """AODV路由表条目"""

    destination: ipaddress.IPv4Address
    dest_seq_num: int
    valid_dest_seq_num: bool
    route_flags: int = 0
    hop_count: int = 0
    next_hop: ipaddress.IPv4Address = field(default_factory=lambda: ipaddress.IPv4Address("0.0.0.0"))
    precursors: List[ipaddress.IPv4Address] = field(default_factory=list)
    lifetime: float = 0.0
    route_state: int = ROUTE_STATE_VALID
    interface: Optional[Interface] = None


@dataclass(slots=True)
class NeighborEntry:
    """AODV邻居表条目"""

    address: ipaddress.IPv4Address
    last_heard: float
    link_state: int
    hello_seq_num: int
    interface: Interface


@dataclass(slots=True)
class RreqCacheEntry:
    """AODV RREQ缓存条目"""

    originator_addr: ipaddress.IPv4Address
    rreq_id: int
    expiry_time: float


@dataclass(slots=True)
class PendingDiscovery:
    """按需路由发现中的状态"""

    dest: ipaddress.IPv4Address
    rreq_id: int
    retry_count: int
    expiry_time: float  # 本次尝试的超时时刻（sim_time）


@dataclass(slots=True)
class AodvHeader:
    """AODV数据包头部"""

    type: int
    flags: int
    reserved: int


@dataclass(slots=True)
class RreqMessage:
    """RREQ消息"""

    header: AodvHeader
    hop_count: int
    rreq_id: int
    dest_addr: int
    dest_seq_num: int
    originator_addr: int
    originator_seq_num: int


@dataclass(slots=True)
class RrepMessage:
    """RREP消息"""

    header: AodvHeader
    hop_count: int
    dest_addr: int
    dest_seq_num: int
    originator_addr: int
    life_time: int  # 生存时间（毫秒）


@dataclass(slots=True)
class UnreachableDest:
    """不可达目标"""

    dest_addr: int
    dest_seq_num: int


@dataclass(slots=True)
class RerrMessage:
    """RERR消息"""

    header: AodvHeader
    dest_count: int
    reserved: int
    unreachable_dests: List[UnreachableDest] = field(default_factory=list)


@dataclass(slots=True)
class HelloMessage:
    """Hello消息"""

    header: AodvHeader
    reserved: int
    seq_num: int
    life_time: int  # 生存时间（毫秒）



# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def make_rreq_cache_key(originator_addr: ipaddress.IPv4Address, rreq_id: int) -> str:
    # 生成RREQ缓存键
    return f"{originator_addr}-{rreq_id}"


def is_seq_num_newer(seq_num1: int, seq_num2: int) -> bool:
    # 检查序列号是否更新（考虑32位整数溢出）
    diff = (seq_num1 - seq_num2) & 0xFFFF_FFFF
    if diff & 0x8000_0000:
        diff -= 0x1_0000_0000
    return diff > 0


def new_route_entry(
    dest: ipaddress.IPv4Address,
    next_hop: ipaddress.IPv4Address,
    hop_count: int,
    dest_seq_num: int,
    valid_seq_num: bool,
    lifetime: float,
    interface: Interface,
) -> RouteEntry:
    # 创建新的路由条目
    return RouteEntry(
        destination=dest,
        dest_seq_num=dest_seq_num,
        valid_dest_seq_num=valid_seq_num,
        route_flags=0,
        hop_count=hop_count,
        next_hop=next_hop,
        precursors=[],
        lifetime=ms.sim_time() + lifetime,
        route_state=ROUTE_STATE_VALID,
        interface=interface,
    )


def new_neighbor_entry(addr: ipaddress.IPv4Address, interface: Interface) -> NeighborEntry:
    # 创建新的邻居条目
    return NeighborEntry(
        address=addr,
        last_heard=ms.sim_time(),
        link_state=ROUTE_STATE_VALID,
        hello_seq_num=0,
        interface=interface,
    )


def _iter_streams(streams: Optional[Dict[int, Stream]]) -> Tuple[Stream, ...]:
    if not streams:
        return ()
    return tuple(streams.values())



# ---------------------------------------------------------------------------
# AODV进程状态
# ---------------------------------------------------------------------------
@ms.process_model("aodv")
class AodvProcess:
    def __init__(self) -> None:
        self.my_module: Optional[SimObj] = None
        self.my_node: Optional[SimObj] = None
        self.ip_module_data: Optional[ModuleData] = None
        self.ip_module: Optional[SimObj] = None

        # UDP通信相关
        self.strm_to_udp: int = -1
        self.strm_from_udp: int = -1
        self.udp_module: Optional[SimObj] = None

        self.enabled_intfs: List[Interface] = []

        # 基本配置
        self.subnet: Optional[ipaddress.IPv4Network] = None
        self.my_address: Optional[ipaddress.IPv4Address] = None
        self.seq_num: int = 0
        self.rreq_id: int = 0

        # 路由表和缓存
        self.route_table: Dict[ipaddress.IPv4Address, RouteEntry] = {}
        self.neighbor_table: Dict[ipaddress.IPv4Address, NeighborEntry] = {}
        self.rreq_cache: Dict[str, RreqCacheEntry] = {}
        # 正在进行中的路由发现（按目的地址）
        self.pending_discoveries: Dict[ipaddress.IPv4Address, PendingDiscovery] = {}

        # 定时器参数
        self.active_route_timeout: float = DEFAULT_ACTIVE_ROUTE_TIMEOUT
        self.hello_interval: float = DEFAULT_HELLO_INTERVAL
        self.allowed_hello_loss: int = DEFAULT_ALLOWED_HELLO_LOSS
        self.rreq_retries: int = DEFAULT_RREQ_RETRIES
        self.net_traversal_time: float = DEFAULT_NET_TRAVERSAL_TIME
        self.cleanup_interval: float = DEFAULT_CLEANUP_INTERVAL

        self.pr_handle = None

    @ms.state_enter("Register", begin=True)
    def enter_register(self) -> None:
        self.my_module = ms.self_obj()
        if self.my_module is None:
            raise RuntimeError("AODV: missing module context during registration")

        self.my_node = ms.topo_parent(self.my_module)
        if self.my_node is None:
            raise RuntimeError("AODV: failed to resolve parent node for AODV module")

        process = ms.pro_self()
        if process is None:
            raise RuntimeError("AODV: missing process context during registration")

        # 注册进程到节点
        self.pr_handle = pr_register(self.my_node.get_id(), self.my_module.get_id(), process, "aodv")
        pr_attr_set(self.pr_handle, "protocol", AttrType.STRING, "aodv")

        # 加个延迟，等待UDP初始化完成
        ms.intrpt_schedule_self(ms.sim_time() + 0.001, 0)


    @ms.state_enter("Init")
    def enter_init(self) -> None:
        if self.my_module is None or self.my_node is None:
            raise RuntimeError("AODV: module context not initialized before init state")

        # 从属性获取管理的子网
        try:
            subnet_str = self.my_module.get_attr_string("Subnet")
        except Exception as exc:
            raise RuntimeError("AODV: subnet attribute is required") from exc

        try:
            subnet = ipaddress.ip_network(subnet_str, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"AODV: invalid subnet {subnet_str!r}") from exc

        # 获取IP模块数据
        self.ip_module = find_node_ip_module(self.my_node)
        if self.ip_module is None:
            raise RuntimeError("AODV: failed to find IP module")

        self.ip_module_data = find_node_ip_module_data(self.my_node)

        # 获取本节点IP地址，也确认哪个接口上启用了AODV协议
        my_address: Optional[ipaddress.IPv4Address] = None
        self.enabled_intfs = []
        for interface in self.ip_module_data.interface_table.values():
            if interface.ip_address in subnet:
                my_address = interface.ip_address

            protocols = {proto.upper() for proto in interface.routing_protocols}
            if "AODV" in protocols:
                self.enabled_intfs.append(interface)

        if my_address is None:
            raise RuntimeError(f"AODV: no interface found in subnet {subnet}")

        # 初始化进程内部数据
        self.subnet = subnet
        self.my_address = my_address
        self.seq_num = 1
        self.rreq_id = 1
        self.route_table.clear()
        self.neighbor_table.clear()
        self.rreq_cache.clear()
        self.pending_discoveries.clear()
        self.active_route_timeout = DEFAULT_ACTIVE_ROUTE_TIMEOUT
        self.hello_interval = DEFAULT_HELLO_INTERVAL
        self.allowed_hello_loss = DEFAULT_ALLOWED_HELLO_LOSS
        self.rreq_retries = DEFAULT_RREQ_RETRIES
        self.net_traversal_time = DEFAULT_NET_TRAVERSAL_TIME
        self.cleanup_interval = DEFAULT_CLEANUP_INTERVAL

        logger.debug("AODV: Module initialized for address %s in subnet %s", my_address, subnet)

        # 初始化UDP通信
        self.init_udp_communication()

        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_exit("Init")
    def exit_init(self) -> None:
        if self.ip_module_data is None or self.my_module is None or self.subnet is None:
            return

        if self.enabled_intfs:
            # 注册到IP模块作为按需路由协议
            on_demand_routing_protocol_register(self.ip_module_data, self.subnet, self.my_module)

            logger.debug("AODV: Initialized for subnet %s", self.subnet)

            # 启动Hello定时器
            ms.intrpt_schedule_self(ms.sim_time() + self.hello_interval, INTRPT_CODE_HELLO_TIMER)

            # 启动清理定时器
            ms.intrpt_schedule_self(ms.sim_time() + self.cleanup_interval, INTRPT_CODE_CLEANUP_TIMER)
        else:
            logger.debug("AODV: No interface enabled for AODV in subnet %s, will disable", self.subnet)


    @ms.state_enter("Idle")
    def enter_idle(self) -> None:
        # AODV进程在空闲状态等待数据包或中断
        return

    @ms.state_exit("Idle")
    def exit_idle(self) -> None:
        intrpt_type = ms.intrpt_type()
        code = ms.intrpt_code()

        if intrpt_type == INTRPT_TYPE_SELF:
            # 自中断处理
            self.handle_self_interrupt(code)
        elif intrpt_type == INTRPT_TYPE_STRM:
            # 流中断，处理UDP数据包
            self.handle_stream_interrupt()
        elif intrpt_type == INTRPT_TYPE_REMOTE:
            # 远程中断，处理IP层的按需路由请求
            self.handle_remote_interrupt()
        else:
            logger.warning("AODV: Unexpected interrupt type: %s", intrpt_type)


    @ms.state_enter("Disabled")
    def enter_disabled(self) -> None:
        return

    @ms.transition("Register", "Init", "f8f9d3d0-d395-4040-b1f3-fe9c291ff5b9")
    def register_to_init(self) -> bool:
        return True

    @ms.transition("Init", "Idle", "da829d69-8237-4aaa-b2ae-b421a702bfa6")
    def init_to_idle(self) -> bool:
        return bool(self.enabled_intfs)

    @ms.transition("Idle", "Idle", "16a90e42-7709-490f-99e2-b73e6adfd1af")
    def idle_to_idle(self) -> bool:
        return True

    @ms.transition("Init", "Disabled", "955c8818-3070-4625-8ba4-d489e090d072")
    def init_to_disabled(self) -> bool:
        return not self.enabled_intfs

    @ms.transition("Disabled", "Disabled", "e63b8f81-59bc-47ef-8a52-77e5fe3b969c")
    def disabled_to_disabled(self) -> bool:
        return True

    # ---------------------------------------------------------- Interrupts --
    def handle_self_interrupt(self, code: int) -> None:
        if code == INTRPT_CODE_HELLO_TIMER:
            # Hello定时器到期
            self.send_hello_message()
            ms.intrpt_schedule_self(ms.sim_time() + self.hello_interval, INTRPT_CODE_HELLO_TIMER)
        elif code == INTRPT_CODE_CLEANUP_TIMER:
            # 清理定时器到期
            self.cleanup_expired_entries()
            ms.intrpt_schedule_self(ms.sim_time() + self.cleanup_interval, INTRPT_CODE_CLEANUP_TIMER)
        else:
            logger.warning("AODV: Unknown self interrupt code: %s", code)

    def handle_stream_interrupt(self) -> None:
        strm_idx = ms.intrpt_strm()
        pkt = ms.pk_get(strm_idx)
        if pkt is None:
            logger.warning("AODV: Failed to get packet from stream %s", strm_idx)
            return

        ici = ms.intrpt_ici()
        if ici is None:
            logger.warning("AODV: No ICI from UDP")
            ms.pk_destroy(pkt)
            return

        try:
            src_addr_int = int(ici.get_int("remote address"))
            src_port = int(ici.get_int("remote port"))
            intf_idx = int(ici.get_int("in intf idx"))
        except Exception as exc:
            logger.warning("AODV: Failed to parse UDP indication ICI: %s", exc)
            ms.pk_destroy(pkt)
            return

        if src_port != AODV_PORT:
            logger.warning("AODV: Received packet from non-AODV port %s", src_port)
            ms.pk_destroy(pkt)
            return

        src_addr = uint32_to_addr(src_addr_int)
        self.process_aodv_packet(pkt, src_addr, intf_idx)

    def handle_remote_interrupt(self) -> None:
        ici = ms.intrpt_ici()
        if ici is None:
            logger.warning("AODV: No ICI from remote interrupt")
            return

        try:
            notify_type = int(ici.get_int("type"))
            dest_addr = ipaddress.ip_address(ici.get_string("dest address"))
        except Exception as exc:
            logger.warning("AODV: malformed remote interrupt ICI: %s", exc)
            return

        if notify_type == ON_DEMAND_NOTIFY_TYPE_NEED:
            # IP层请求查找到目标的路由
            logger.debug("AODV: Route discovery requested for %s", dest_addr)
            self.initiate_route_discovery(dest_addr)

    # ----------------------------------------------------------- UDP Setup --
    def init_udp_communication(self) -> None:
        if self.my_module is None or self.my_node is None:
            raise RuntimeError("AODV: init_udp_communication called without module context")

        out_streams = _iter_streams(ms.get_out_streams())
        in_streams = _iter_streams(ms.get_in_streams())

        if not out_streams or not in_streams:
            raise RuntimeError("AODV: Failed to find UDP streams")

        strm_to_udp = out_streams[0]
        strm_from_udp = in_streams[0]

        if strm_from_udp.src is not strm_to_udp.dst:
            raise RuntimeError("AODV: UDP streams are not connected")

        # 通过进程发现，检查相连的模块是否是UDP模块
        attrs = [
            ProcessAttribute("protocol", AttrType.STRING, "udp"),
            ProcessAttribute("node objid", AttrType.OBJ_ID, self.my_node.get_id()),
        ]
        handles = pr_discover(self.my_module.get_id(), *attrs)
        if not handles:
            raise RuntimeError("AODV: Failed to discover UDP process")
        if len(handles) != 1:
            raise RuntimeError("AODV: Either no or more than one connected UDP process found")

        udp_module_id = int(pr_attr_get(handles[0], "module objid"))
        if udp_module_id != strm_to_udp.dst.get_id():
            raise RuntimeError("AODV: UDP module is not connected to expected stream")

        self.udp_module = strm_to_udp.dst

        model_name = self.udp_module.get_attr_string("process model")
        if model_name != "udp":
            raise RuntimeError("AODV: Connected module is not UDP")

        self.strm_to_udp = strm_to_udp.src_index
        self.strm_from_udp = strm_from_udp.dst_index

        # 将AODV注册为UDP应用
        self.register_udp_app()

        logger.debug("AODV: UDP communication initialized on port %s", AODV_PORT)

    def register_udp_app(self) -> None:
        if self.udp_module is None or self.my_module is None:
            raise RuntimeError("AODV: register_udp_app called before UDP module resolved")

        ici = ms.ici_create("udp_command")
        ici.set_string("command", "listen")
        ici.set_int("app module id", self.my_module.get_id())
        ici.set_int("local port", AODV_PORT)

        ms.ici_install(ici)
        ms.intrpt_schedule_remote(ms.sim_time(), 0, self.udp_module)
        ms.ici_install(None)

    # --------------------------------------------------------------- Helpers --
    def send_udp_packet(self, pkt, dest_addr: ipaddress.IPv4Address, dest_port: int) -> None:
        if self.strm_to_udp < 0:
            logger.warning("AODV: Stream to UDP not ready; dropping packet")
            ms.pk_destroy(pkt)
            return

        ici = ms.ici_create("udp_ind")
        ici.set_int("remote address", addr_to_uint32(dest_addr))
        ici.set_int("remote port", dest_port)
        ici.set_int("local port", AODV_PORT)

        ms.ici_install(ici)
        ms.pk_stamp(pkt)
        ms.pk_send(pkt, self.strm_to_udp)
        ms.ici_install(None)

    def broadcast_packet(self, pkt) -> None:
        # 向所有启用了的接口广播
        for _interface in self.enabled_intfs:
            self.send_udp_packet(ms.pk_copy(pkt), LIMITED_BROADCAST_ADDR, AODV_PORT)
        ms.pk_destroy(pkt)

    def broadcast_rreq(self, rreq: RreqMessage) -> None:
        pkt = ms.pk_create_fmt(AODV_PACKET_FORMAT)
        ms.pk_nfd_set_pointer(pkt, "header", rreq.header)
        ms.pk_nfd_set_pointer(pkt, "data", rreq)
        self.broadcast_packet(pkt)

    def notify_ip_route_result(self, dest_addr: ipaddress.IPv4Address, result: int) -> None:
        if self.ip_module is None:
            logger.warning("AODV: IP module not resolved, cannot notify route result")
            return

        # 当前目的的路由发现已结束（无论成功还是失败）
        self.pending_discoveries.pop(dest_addr, None)

        ici = ms.ici_create("ip_on_demand_routing_notify")
        ici.set_int("type", result)
        ici.set_string("dest address", str(dest_addr))

        ms.ici_install(ici)
        ms.intrpt_schedule_remote(ms.sim_time(), REMOTE_INTRPT_CODE_ON_DEMAND_NOTIFY, self.ip_module)
        ms.ici_install(None)

        logger.debug("AODV: Notified IP layer - route result %s for %s", result, dest_addr)

    def send_hello_message(self) -> None:
        if self.my_address is None:
            return

        # 增加序列号
        self.seq_num += 1

        hello = HelloMessage(
            header=AodvHeader(type=AODV_MSG_TYPE_HELLO, flags=0, reserved=0),
            reserved=0,
            seq_num=self.seq_num,
            life_time=int(self.active_route_timeout * 1000),
        )

        pkt = ms.pk_create_fmt(AODV_PACKET_FORMAT)
        ms.pk_nfd_set_pointer(pkt, "header", hello.header)
        ms.pk_nfd_set_pointer(pkt, "data", hello)

        # 向所有启用AODV的接口广播Hello消息
        self.broadcast_packet(pkt)

    def cleanup_expired_entries(self) -> None:
        now = ms.sim_time()

        # 清理过期路由
        for dest, route in list(self.route_table.items()):
            if now > route.lifetime:
                self.remove_from_ip_routing_table(dest, route)
                del self.route_table[dest]
                logger.debug("AODV: Removed expired route to %s", dest)

        timeout = self.hello_interval * float(self.allowed_hello_loss)
        # 清理过期邻居
        for addr, neighbor in list(self.neighbor_table.items()):
            if now - neighbor.last_heard > timeout:
                del self.neighbor_table[addr]
                logger.debug("AODV: Removed expired neighbor %s", addr)
                self.invalidate_routes_via_neighbor(addr)

        # 清理过期RREQ缓存
        for key, entry in list(self.rreq_cache.items()):
            if now > entry.expiry_time:
                del self.rreq_cache[key]

        # 处理路由发现的超时与重试
        for dest, pending in list(self.pending_discoveries.items()):
            if now < pending.expiry_time:
                continue

            # 还可以重试，继续发送 RREQ
            if pending.retry_count < self.rreq_retries:
                self._send_rreq_for_discovery(pending)
            else:
                # 重试次数已用尽，通知 IP 层失败
                self.notify_ip_route_result(dest, ON_DEMAND_NOTIFY_TYPE_FAILED)
                logger.debug(
                    "AODV: Route discovery failed for %s after %s attempts",
                    dest,
                    pending.retry_count,
                )

    def remove_from_ip_routing_table(self, dest: ipaddress.IPv4Address, route: RouteEntry) -> None:
        if self.ip_module_data is None:
            return

        prefix = ipaddress.IPv4Network((dest, 32))
        entries = get_routing_entries_for_dest(self.ip_module_data, prefix)

        for entry in entries:
            if entry.route_source == ROUTE_SOURCE_AODV and entry.extra_info is route:
                remove_route_entry(self.ip_module_data, entry)
                break

    def invalidate_routes_via_neighbor(self, neighbor_addr: ipaddress.IPv4Address) -> None:
        invalid_routes: List[ipaddress.IPv4Address] = []

        for dest, route in self.route_table.items():
            if route.next_hop == neighbor_addr and route.route_state == ROUTE_STATE_VALID:
                route.route_state = ROUTE_STATE_INVALID
                invalid_routes.append(dest)
                self.remove_from_ip_routing_table(dest, route)

        if invalid_routes:
            self.send_rerr_for_invalid_routes(invalid_routes)

    def send_rerr_for_invalid_routes(self, invalid_routes: List[ipaddress.IPv4Address]) -> None:
        if not invalid_routes:
            return

        rerr = RerrMessage(
            header=AodvHeader(type=AODV_MSG_TYPE_RERR, flags=0, reserved=0),
            dest_count=len(invalid_routes),
            reserved=0,
            unreachable_dests=[],
        )

        for dest in invalid_routes:
            route = self.route_table.get(dest)
            if route is None:
                continue
            rerr.unreachable_dests.append(
                UnreachableDest(dest_addr=addr_to_uint32(dest), dest_seq_num=route.dest_seq_num)
            )

        pkt = ms.pk_create_fmt(AODV_PACKET_FORMAT)
        ms.pk_nfd_set_pointer(pkt, "header", rerr.header)
        ms.pk_nfd_set_pointer(pkt, "data", rerr)

        self.broadcast_packet(pkt)
        logger.debug("AODV: Sent RERR for %d invalid routes", len(invalid_routes))

    # -------------------------------------------------------- Packet Handle --
    def process_aodv_packet(self, pkt, src_addr: ipaddress.IPv4Address, intf_idx: int) -> None:
        try:
            pkt_format = ms.pk_format(pkt)
            if pkt_format != AODV_PACKET_FORMAT:
                logger.warning("AODV: Unexpected packet format: %s", pkt_format)
                return

            header_obj = ms.pk_nfd_get_pointer(pkt, "header")
            if not isinstance(header_obj, AodvHeader):
                logger.warning("AODV: Failed to get AODV header")
                return

            msg_type = header_obj.type
            if msg_type == AODV_MSG_TYPE_RREQ:
                self.process_rreq(pkt, src_addr, intf_idx)
            elif msg_type == AODV_MSG_TYPE_RREP:
                self.process_rrep(pkt, src_addr, intf_idx)
            elif msg_type == AODV_MSG_TYPE_RERR:
                self.process_rerr(pkt, src_addr, intf_idx)
            elif msg_type == AODV_MSG_TYPE_HELLO:
                self.process_hello(pkt, src_addr, intf_idx)
            else:
                logger.warning("AODV: Unknown message type: %s", msg_type)
        finally:
            ms.pk_destroy(pkt)

    def process_rreq(self, pkt, src_addr: ipaddress.IPv4Address, intf_idx: int) -> None:
        rreq = ms.pk_nfd_get_pointer(pkt, "data")
        if not isinstance(rreq, RreqMessage):
            logger.warning("AODV: Failed to get RREQ message")
            return

        originator_addr = uint32_to_addr(rreq.originator_addr)
        dest_addr = uint32_to_addr(rreq.dest_addr)

        logger.debug(
            "AODV: Received RREQ from %s for %s (ID: %s, Hops: %s)",
            src_addr,
            dest_addr,
            rreq.rreq_id,
            rreq.hop_count,
        )

        cache_key = make_rreq_cache_key(originator_addr, rreq.rreq_id)
        if cache_key in self.rreq_cache:
            logger.debug("AODV: Duplicate RREQ ignored")
            return

        now = ms.sim_time()
        self.rreq_cache[cache_key] = RreqCacheEntry(
            originator_addr=originator_addr,
            rreq_id=rreq.rreq_id,
            expiry_time=now + self.net_traversal_time,
        )

        self.update_route_to_originator(rreq, src_addr, intf_idx)

        if self.my_address is None:
            return

        if dest_addr == self.my_address:
            # 本节点是目标，发送RREP
            self.send_rrep(originator_addr, src_addr, rreq)
            return

        route = self.route_table.get(dest_addr)
        if (
            route is not None
            and route.route_state == ROUTE_STATE_VALID
            and now < route.lifetime
            and self.can_reply_with_route(rreq, route)
        ):
            self.send_rrep_from_route(originator_addr, src_addr, dest_addr, route, rreq)
            return

        self.forward_rreq(rreq, src_addr)

    def update_route_to_originator(self, rreq: RreqMessage, src_addr: ipaddress.IPv4Address, intf_idx: int) -> None:
        if self.ip_module_data is None:
            return

        originator_addr = uint32_to_addr(rreq.originator_addr)
        interface = self.ip_module_data.interface_table.get(intf_idx)
        if interface is None:
            logger.warning("AODV: Cannot find interface for source %s", src_addr)
            return

        hop_count = rreq.hop_count + 1
        lifetime = ms.sim_time() + self.active_route_timeout

        route = self.route_table.get(originator_addr)
        if route is not None:
            if is_seq_num_newer(rreq.originator_seq_num, route.dest_seq_num) or (
                rreq.originator_seq_num == route.dest_seq_num and hop_count < route.hop_count
            ):
                route.dest_seq_num = rreq.originator_seq_num
                route.valid_dest_seq_num = True
                route.hop_count = hop_count
                route.next_hop = src_addr
                route.lifetime = lifetime
                route.route_state = ROUTE_STATE_VALID
                route.interface = interface
                self.add_to_ip_routing_table(originator_addr, route)
        else:
            route = new_route_entry(
                dest=originator_addr,
                next_hop=src_addr,
                hop_count=hop_count,
                dest_seq_num=rreq.originator_seq_num,
                valid_seq_num=True,
                lifetime=self.active_route_timeout,
                interface=interface,
            )
            self.route_table[originator_addr] = route
            self.add_to_ip_routing_table(originator_addr, route)

    def can_reply_with_route(self, rreq: RreqMessage, route: RouteEntry) -> bool:
        if rreq.header.flags & AODV_FLAG_DEST_ONLY:
            return False

        if rreq.header.flags & AODV_FLAG_UNKNOWN_SEQ_NUM:
            return route.valid_dest_seq_num

        return route.valid_dest_seq_num and route.dest_seq_num >= rreq.dest_seq_num

    def send_rrep(
        self,
        dest_addr: ipaddress.IPv4Address,
        next_hop: ipaddress.IPv4Address,
        rreq: RreqMessage,
    ) -> None:
        if self.my_address is None:
            return

        self.seq_num += 1

        rrep = RrepMessage(
            header=AodvHeader(type=AODV_MSG_TYPE_RREP, flags=0, reserved=0),
            hop_count=0,
            dest_addr=addr_to_uint32(self.my_address),
            dest_seq_num=self.seq_num,
            originator_addr=rreq.originator_addr,
            life_time=int(self.active_route_timeout * 1000 * 2),
        )

        pkt = ms.pk_create_fmt(AODV_PACKET_FORMAT)
        ms.pk_nfd_set_pointer(pkt, "header", rrep.header)
        ms.pk_nfd_set_pointer(pkt, "data", rrep)

        self.send_udp_packet(pkt, next_hop, AODV_PORT)
        logger.debug("AODV: Sent RREP to %s for destination %s", next_hop, dest_addr)

    def send_rrep_from_route(
        self,
        originator_addr: ipaddress.IPv4Address,
        next_hop: ipaddress.IPv4Address,
        dest_addr: ipaddress.IPv4Address,
        route: RouteEntry,
        rreq: RreqMessage,
    ) -> None:
        remaining = max(0.0, route.lifetime - ms.sim_time())
        rrep = RrepMessage(
            header=AodvHeader(type=AODV_MSG_TYPE_RREP, flags=0, reserved=0),
            hop_count=route.hop_count,
            dest_addr=addr_to_uint32(dest_addr),
            dest_seq_num=route.dest_seq_num,
            originator_addr=rreq.originator_addr,
            life_time=int(remaining * 1000),
        )

        pkt = ms.pk_create_fmt(AODV_PACKET_FORMAT)
        ms.pk_nfd_set_pointer(pkt, "header", rrep.header)
        ms.pk_nfd_set_pointer(pkt, "data", rrep)

        self.send_udp_packet(pkt, next_hop, AODV_PORT)
        logger.debug(
            "AODV: Sent RREP from route to %s for destination %s (hops: %s)",
            next_hop,
            dest_addr,
            route.hop_count,
        )

    def forward_rreq(self, rreq: RreqMessage, src_addr: ipaddress.IPv4Address) -> None:
        rreq.hop_count += 1

        pkt = ms.pk_create_fmt(AODV_PACKET_FORMAT)
        ms.pk_nfd_set_pointer(pkt, "header", rreq.header)
        ms.pk_nfd_set_pointer(pkt, "data", rreq)

        self.broadcast_packet(pkt)
        logger.debug(
            "AODV: Forwarded RREQ for %s (hops: %s)",
            uint32_to_addr(rreq.dest_addr),
            rreq.hop_count,
        )

    def add_to_ip_routing_table(self, dest: ipaddress.IPv4Address, route: RouteEntry) -> None:
        if self.ip_module_data is None or route.interface is None:
            logger.warning("AODV: cannot add route to IP table without module data or interface")
            return

        self.remove_from_ip_routing_table(dest, route)

        prefix = ipaddress.IPv4Network((dest, 32))
        rib_entry = RIBEntry(
            destination=prefix,
            next_hop=route.next_hop,
            out_interface=route.interface,
            metric=int(route.hop_count),
            admin_dist=ADMIN_DIST_AODV,
            route_source=ROUTE_SOURCE_AODV,
            extra_info=route,
        )

        add_route_entry(self.ip_module_data, rib_entry)
        logger.debug(
            "AODV: Added route to IP table: %s via %s (hops: %s)",
            dest,
            route.next_hop,
            route.hop_count,
        )

    def process_rrep(self, pkt, src_addr: ipaddress.IPv4Address, intf_idx: int) -> None:
        rrep = ms.pk_nfd_get_pointer(pkt, "data")
        if not isinstance(rrep, RrepMessage):
            logger.warning("AODV: Failed to get RREP message")
            return

        dest_addr = uint32_to_addr(rrep.dest_addr)
        originator_addr = uint32_to_addr(rrep.originator_addr)

        logger.debug(
            "AODV: Received RREP from %s for %s (hops: %s)",
            src_addr,
            dest_addr,
            rrep.hop_count,
        )

        if self.ip_module_data is None:
            return

        interface = self.ip_module_data.interface_table.get(intf_idx)
        if interface is None:
            logger.warning("AODV: Cannot find interface for source %s", src_addr)
            return

        hop_count = rrep.hop_count + 1
        should_update = False
        current_route = self.route_table.get(dest_addr)

        if current_route is not None:
            if is_seq_num_newer(rrep.dest_seq_num, current_route.dest_seq_num) or (
                rrep.dest_seq_num == current_route.dest_seq_num and hop_count < current_route.hop_count
            ):
                should_update = True
        else:
            should_update = True

        if should_update:
            route = new_route_entry(
                dest=dest_addr,
                next_hop=src_addr,
                hop_count=hop_count,
                dest_seq_num=rrep.dest_seq_num,
                valid_seq_num=True,
                lifetime=float(rrep.life_time) / 1000.0,
                interface=interface,
            )
            self.route_table[dest_addr] = route
            self.add_to_ip_routing_table(dest_addr, route)

            logger.debug(
                "AODV: Updated route to %s via %s (hops: %s, seq: %s)",
                dest_addr,
                src_addr,
                hop_count,
                rrep.dest_seq_num,
            )

        if self.my_address is not None and originator_addr == self.my_address:
            self.notify_ip_route_result(dest_addr, ON_DEMAND_NOTIFY_TYPE_FOUND)
            return

        route_to_origin = self.route_table.get(originator_addr)
        if (
            route_to_origin is not None
            and route_to_origin.route_state == ROUTE_STATE_VALID
            and ms.sim_time() < route_to_origin.lifetime
        ):
            rrep.hop_count += 1

            pkt_fwd = ms.pk_create_fmt(AODV_PACKET_FORMAT)
            ms.pk_nfd_set_pointer(pkt_fwd, "header", rrep.header)
            ms.pk_nfd_set_pointer(pkt_fwd, "data", rrep)

            self.send_udp_packet(pkt_fwd, route_to_origin.next_hop, AODV_PORT)
            logger.debug("AODV: Forwarded RREP to %s (hops: %s)", route_to_origin.next_hop, rrep.hop_count)
        else:
            logger.warning("AODV: No route to originator %s, dropping RREP", originator_addr)

    def process_rerr(self, pkt, src_addr: ipaddress.IPv4Address, intf_idx: int) -> None:
        rerr = ms.pk_nfd_get_pointer(pkt, "data")
        if not isinstance(rerr, RerrMessage):
            logger.warning("AODV: Failed to get RERR message")
            return

        logger.debug("AODV: Received RERR from %s for %s destinations", src_addr, rerr.dest_count)

        affected_routes: List[ipaddress.IPv4Address] = []
        for unreachable in rerr.unreachable_dests:
            dest_addr = uint32_to_addr(unreachable.dest_addr)
            route = self.route_table.get(dest_addr)
            if (
                route is not None
                and route.next_hop == src_addr
                and route.route_state == ROUTE_STATE_VALID
            ):
                if route.valid_dest_seq_num and is_seq_num_newer(unreachable.dest_seq_num, route.dest_seq_num):
                    route.dest_seq_num = unreachable.dest_seq_num
                route.route_state = ROUTE_STATE_INVALID
                affected_routes.append(dest_addr)
                self.remove_from_ip_routing_table(dest_addr, route)
                logger.debug("AODV: Invalidated route to %s due to RERR", dest_addr)

        if affected_routes:
            self.propagate_rerr(rerr, src_addr, affected_routes)

    def propagate_rerr(
        self,
        rerr: RerrMessage,
        src_addr: ipaddress.IPv4Address,
        affected_routes: List[ipaddress.IPv4Address],
    ) -> None:
        pkt = ms.pk_create_fmt(AODV_PACKET_FORMAT)
        ms.pk_nfd_set_pointer(pkt, "header", rerr.header)
        ms.pk_nfd_set_pointer(pkt, "data", rerr)

        self.broadcast_packet(pkt)
        logger.debug("AODV: Propagated RERR for %d routes", len(affected_routes))

    def process_hello(self, pkt, src_addr: ipaddress.IPv4Address, intf_idx: int) -> None:
        hello = ms.pk_nfd_get_pointer(pkt, "data")
        if not isinstance(hello, HelloMessage):
            logger.warning("AODV: Failed to get Hello message")
            return

        if self.ip_module_data is None:
            return

        interface = self.ip_module_data.interface_table.get(intf_idx)
        if interface is None:
            logger.warning("AODV: Cannot find interface for source %s", src_addr)
            return

        neighbor = self.neighbor_table.get(src_addr)
        if neighbor is not None:
            neighbor.last_heard = ms.sim_time()
            neighbor.hello_seq_num = hello.seq_num
            neighbor.link_state = ROUTE_STATE_VALID
        else:
            neighbor = new_neighbor_entry(src_addr, interface)
            neighbor.hello_seq_num = hello.seq_num
            self.neighbor_table[src_addr] = neighbor
            logger.debug("AODV: Discovered new neighbor %s", src_addr)

        if src_addr not in self.route_table:
            route = new_route_entry(
                dest=src_addr,
                next_hop=src_addr,
                hop_count=1,
                dest_seq_num=hello.seq_num,
                valid_seq_num=True,
                lifetime=float(hello.life_time) / 1000.0,
                interface=interface,
            )
            self.route_table[src_addr] = route
            self.add_to_ip_routing_table(src_addr, route)

    # ----------------------------------------------------------- Discovery --
    def initiate_route_discovery(self, dest_addr: ipaddress.IPv4Address) -> None:
        if self.my_address is None:
            return

        now = ms.sim_time()
        route = self.route_table.get(dest_addr)
        if route is not None and route.route_state == ROUTE_STATE_VALID and now < route.lifetime:
            self.notify_ip_route_result(dest_addr, ON_DEMAND_NOTIFY_TYPE_FOUND)
            return

        # 已经有对该目的的路由发现正在进行中，避免重复发起
        if dest_addr in self.pending_discoveries:
            logger.debug("AODV: Route discovery already in progress for %s", dest_addr)
            return

        # 为本次路由发现分配一个新的 RREQ ID
        rreq_id = self.rreq_id
        self.rreq_id += 1

        pending = PendingDiscovery(
            dest=dest_addr,
            rreq_id=rreq_id,
            retry_count=0,
            expiry_time=now,  # 立即触发第一次发送
        )
        self.pending_discoveries[dest_addr] = pending

        self._send_rreq_for_discovery(pending)

    def _send_rreq_for_discovery(self, pending: PendingDiscovery) -> None:
        """根据 pending 状态构造并发送一次 RREQ，同时更新重试计数和超时时间。"""
        if self.my_address is None:
            return

        now = ms.sim_time()
        dest_addr = pending.dest

        route = self.route_table.get(dest_addr)

        # 每次尝试递增本端序列号
        self.seq_num += 1

        rreq_header = AodvHeader(type=AODV_MSG_TYPE_RREQ, flags=0, reserved=0)
        rreq = RreqMessage(
            header=rreq_header,
            hop_count=0,
            rreq_id=pending.rreq_id,
            dest_addr=addr_to_uint32(dest_addr),
            dest_seq_num=0,
            originator_addr=addr_to_uint32(self.my_address),
            originator_seq_num=self.seq_num,
        )

        if route is not None and route.valid_dest_seq_num:
            rreq.dest_seq_num = route.dest_seq_num
        else:
            rreq.header.flags |= AODV_FLAG_UNKNOWN_SEQ_NUM

        self.broadcast_rreq(rreq)

        pending.retry_count += 1
        pending.expiry_time = now + self.net_traversal_time

        logger.debug(
            "AODV: Sent RREQ for %s (RREQ ID: %s, attempt: %s)",
            dest_addr,
            pending.rreq_id,
            pending.retry_count,
        )
