#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Springa — Price drop protection and autosell engine. Tracks asset levels against
a high-water mark and triggers automatic sell when thresholds are breached.
Designed for EVM-compatible flows; all addresses are 40-hex EIP-55 style.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# -----------------------------------------------------------------------------
# SPRG constants (immutable; do not reassign)
# ------------------------------------------------------------------------------

SPRG_VERSION = "2.1.0"
SPRG_DOMAIN_HASH = "0x7f3e9a2c5d8b1E4f6A0c3D5e8B2d4F7a9C1e6A0b"
SPRG_BPS_DENOM = 10000
SPRG_MAX_DROP_BPS = 9500
SPRG_MIN_FLOOR_BPS = 100
SPRG_DEFAULT_COOLDOWN_SEC = 300
SPRG_MAX_COOLDOWN_SEC = 86400
SPRG_MIN_COOLDOWN_SEC = 60
SPRG_CONFIG_SALT = 0x4A8c1E5f9B2d6F0a3C7e1B4D8f2A5c9E0b3F6a1D
SPRG_GUARDIAN_DOMAIN = "SpringaGuardian.v2"
SPRG_TRIGGER_KIND_DROP = 1
SPRG_TRIGGER_KIND_FLOOR = 2
SPRG_TRIGGER_KIND_BOTH = 3
SPRG_STATUS_ACTIVE = 1
SPRG_STATUS_TRIGGERED = 2
SPRG_STATUS_SOLD = 3
SPRG_STATUS_DISABLED = 4
SPRG_STATUS_COOLDOWN = 5

# Immutable deployment-style addresses (40 hex EIP-55 style; unique)
SPRG_GUARDIAN_ADDRESS = "0xB2c5E8f1A4d7b0C3e6F9a2B5d8E1c4F7a0B3D6e9"
SPRG_TREASURY_ADDRESS = "0x3D6f9A2c5E8b1D4e7F0a3C6d9B2e5F8a1C4d7E0"
SPRG_FEE_SINK_ADDRESS = "0x5E8b1D4f7A0c3E6F9a2B5d8E1c4F7a0B3D6e9f2"
SPRG_KEEPER_ADDRESS = "0x8F1a4D7b0C3e6F9A2b5D8e1C4f7A0b3D6E9f2a5"
SPRG_SENTINEL_ADDRESS = "0x1C4f7A0b3D6e9F2a5C8d1E4f7A0b3D6e9F2a5B8"


# -----------------------------------------------------------------------------
# EIP-55 checksum
# ------------------------------------------------------------------------------

def _keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception:
        try:
            import sha3
            return sha3.keccak_256(data).digest()
        except Exception:
            return hashlib.sha3_256(data).digest()


def to_checksum_address(addr: str) -> str:
    addr = addr.lower().replace("0x", "")
    if len(addr) != 40:
        return "0x" + addr
    h = _keccak256(addr.encode("ascii")).hex()
    out = "0x"
    for i, c in enumerate(addr):
        nibble = int(h[i], 16)
        if nibble >= 8 and c in "abcdef":
            out += c.upper()
        else:
            out += c
    return out


def random_address_40hex() -> str:
    raw = "0x" + secrets.token_hex(20)
    return to_checksum_address(raw)


# -----------------------------------------------------------------------------
# SPRG exceptions (unique names)
# ------------------------------------------------------------------------------

class SPRG_ZeroAddress(Exception):
    pass


class SPRG_ZeroAmount(Exception):
    pass


class SPRG_InvalidDropBps(Exception):
    pass


class SPRG_InvalidFloorBps(Exception):
    pass


class SPRG_CooldownActive(Exception):
    pass


class SPRG_TriggerAlreadyFired(Exception):
    pass


class SPRG_GuardianOnly(Exception):
    pass


class SPRG_NotKeeper(Exception):
    pass


class SPRG_TransferFailed(Exception):
    pass


class SPRG_PriceStale(Exception):
    pass


class SPRG_Disabled(Exception):
    pass


class SPRG_AboveFloor(Exception):
    pass


class SPRG_BelowMinCooldown(Exception):
    pass


class SPRG_AboveMaxCooldown(Exception):
    pass


class SPRG_AssetNotWhitelisted(Exception):
    pass


class SPRG_PositionNotFound(Exception):
    pass


# -----------------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------------------

class TriggerKind(Enum):
    DROP = SPRG_TRIGGER_KIND_DROP
    FLOOR = SPRG_TRIGGER_KIND_FLOOR
    BOTH = SPRG_TRIGGER_KIND_BOTH


class PositionStatus(Enum):
    ACTIVE = SPRG_STATUS_ACTIVE
    TRIGGERED = SPRG_STATUS_TRIGGERED
    SOLD = SPRG_STATUS_SOLD
    DISABLED = SPRG_STATUS_DISABLED
    COOLDOWN = SPRG_STATUS_COOLDOWN


@dataclass
class PriceSnapshot:
    asset_id: str
    price_wei: int
    timestamp: float
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "price_wei": self.price_wei,
            "timestamp": self.timestamp,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PriceSnapshot":
        return cls(
            asset_id=d.get("asset_id", ""),
            price_wei=int(d.get("price_wei", 0)),
            timestamp=float(d.get("timestamp", 0)),
            source=d.get("source", ""),
        )


@dataclass
class Position:
    position_id: str
    owner: str
    asset_id: str
    amount_wei: int
    high_water_mark_wei: int
    floor_price_wei: int
    drop_bps: int
    floor_bps: int
    trigger_kind: int
    status: int
    created_at: float
    last_updated_at: float
    triggered_at: float
    cooldown_until: float
    sold_amount_wei: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "position_id": self.position_id,
            "owner": self.owner,
            "asset_id": self.asset_id,
            "amount_wei": self.amount_wei,
            "high_water_mark_wei": self.high_water_mark_wei,
            "floor_price_wei": self.floor_price_wei,
            "drop_bps": self.drop_bps,
            "floor_bps": self.floor_bps,
            "trigger_kind": self.trigger_kind,
            "status": self.status,
            "created_at": self.created_at,
            "last_updated_at": self.last_updated_at,
            "triggered_at": self.triggered_at,
            "cooldown_until": self.cooldown_until,
            "sold_amount_wei": self.sold_amount_wei,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Position":
        return cls(
            position_id=d.get("position_id", ""),
            owner=d.get("owner", ""),
            asset_id=d.get("asset_id", ""),
            amount_wei=int(d.get("amount_wei", 0)),
            high_water_mark_wei=int(d.get("high_water_mark_wei", 0)),
            floor_price_wei=int(d.get("floor_price_wei", 0)),
            drop_bps=int(d.get("drop_bps", 2000)),
            floor_bps=int(d.get("floor_bps", 500)),
            trigger_kind=int(d.get("trigger_kind", SPRG_TRIGGER_KIND_BOTH)),
            status=int(d.get("status", SPRG_STATUS_ACTIVE)),
            created_at=float(d.get("created_at", 0)),
            last_updated_at=float(d.get("last_updated_at", 0)),
            triggered_at=float(d.get("triggered_at", 0)),
            cooldown_until=float(d.get("cooldown_until", 0)),
            sold_amount_wei=int(d.get("sold_amount_wei", 0)),
            metadata=dict(d.get("metadata", {})),
        )


@dataclass
class SellOrder:
    order_id: str
    position_id: str
    asset_id: str
    amount_wei: int
    executed_price_wei: int
    executed_at: float
    tx_hash: str = ""
    status: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "order_id": self.order_id,
            "position_id": self.position_id,
            "asset_id": self.asset_id,
            "amount_wei": self.amount_wei,
            "executed_price_wei": self.executed_price_wei,
            "executed_at": self.executed_at,
            "tx_hash": self.tx_hash,
            "status": self.status,
        }


# -----------------------------------------------------------------------------
# Price feed abstraction
# ------------------------------------------------------------------------------

class PriceFeedBase:
    def get_price(self, asset_id: str) -> Optional[PriceSnapshot]:
        raise NotImplementedError

    def get_prices(self, asset_ids: List[str]) -> Dict[str, PriceSnapshot]:
        out = {}
        for aid in asset_ids:
            s = self.get_price(aid)
            if s:
                out[aid] = s
        return out


class MockPriceFeed(PriceFeedBase):
    def __init__(self, prices: Optional[Dict[str, int]] = None, drift_bps: int = 0):
        self._prices = dict(prices or {})
        self._drift_bps = drift_bps

    def set_price(self, asset_id: str, price_wei: int) -> None:
        self._prices[asset_id] = price_wei

    def get_price(self, asset_id: str) -> Optional[PriceSnapshot]:
        p = self._prices.get(asset_id)
        if p is None:
            return None
        if self._drift_bps:
            import random
            p = p + (p * random.randint(-self._drift_bps, self._drift_bps) // SPRG_BPS_DENOM)
        return PriceSnapshot(asset_id=asset_id, price_wei=max(0, p), timestamp=time.time(), source="mock")


# -----------------------------------------------------------------------------
# Drop guard logic (price drop protection)
# ------------------------------------------------------------------------------

def compute_drop_bps(high_wei: int, current_wei: int) -> int:
    if high_wei == 0:
        return 0
    if current_wei >= high_wei:
        return 0
    return ((high_wei - current_wei) * SPRG_BPS_DENOM) // high_wei


def compute_floor_price_wei(high_wei: int, floor_bps: int) -> int:
    return (high_wei * floor_bps) // SPRG_BPS_DENOM


def should_trigger_drop(current_wei: int, high_wei: int, drop_bps: int) -> bool:
    if high_wei == 0:
        return False
    return compute_drop_bps(high_wei, current_wei) >= drop_bps


def should_trigger_floor(current_wei: int, floor_price_wei: int) -> bool:
    return current_wei <= floor_price_wei and floor_price_wei > 0


def should_trigger(position: Position, snapshot: PriceSnapshot) -> bool:
    if position.status != SPRG_STATUS_ACTIVE:
        return False
    if position.trigger_kind == SPRG_TRIGGER_KIND_DROP:
        return should_trigger_drop(snapshot.price_wei, position.high_water_mark_wei, position.drop_bps)
    if position.trigger_kind == SPRG_TRIGGER_KIND_FLOOR:
        return should_trigger_floor(snapshot.price_wei, position.floor_price_wei)
    if position.trigger_kind == SPRG_TRIGGER_KIND_BOTH:
        return should_trigger_drop(snapshot.price_wei, position.high_water_mark_wei, position.drop_bps) or should_trigger_floor(snapshot.price_wei, position.floor_price_wei)
    return False


# -----------------------------------------------------------------------------
# Springa engine (core)
# ------------------------------------------------------------------------------

class SpringaEngine:
    def __init__(
        self,
        guardian: str = SPRG_GUARDIAN_ADDRESS,
        treasury: str = SPRG_TREASURY_ADDRESS,
        fee_sink: str = SPRG_FEE_SINK_ADDRESS,
        keeper: str = SPRG_KEEPER_ADDRESS,
        sentinel: str = SPRG_SENTINEL_ADDRESS,
        default_cooldown_sec: int = SPRG_DEFAULT_COOLDOWN_SEC,
        price_feed: Optional[PriceFeedBase] = None,
    ):
        self._guardian = to_checksum_address(guardian)
        self._treasury = to_checksum_address(treasury)
        self._fee_sink = to_checksum_address(fee_sink)
        self._keeper = to_checksum_address(keeper)
        self._sentinel = to_checksum_address(sentinel)
        self._default_cooldown_sec = default_cooldown_sec
        self._price_feed = price_feed or MockPriceFeed()
        self._positions: Dict[str, Position] = {}
        self._sell_orders: Dict[str, SellOrder] = {}
        self._whitelist: set = set()
        self._position_id_seq = 0
        self._order_id_seq = 0

    def _next_position_id(self) -> str:
        self._position_id_seq += 1
        return f"SPRG_POS_{self._position_id_seq}_{int(time.time() * 1000)}"

    def _next_order_id(self) -> str:
        self._order_id_seq += 1
        return f"SPRG_ORD_{self._order_id_seq}_{int(time.time() * 1000)}"

    @property
    def guardian(self) -> str:
        return self._guardian

    @property
    def treasury(self) -> str:
        return self._treasury

    @property
    def fee_sink(self) -> str:
        return self._fee_sink

    @property
    def keeper(self) -> str:
        return self._keeper

    @property
    def sentinel(self) -> str:
        return self._sentinel

    def add_to_whitelist(self, asset_id: str) -> None:
        self._whitelist.add(asset_id)

    def remove_from_whitelist(self, asset_id: str) -> None:
        self._whitelist.discard(asset_id)

    def is_whitelisted(self, asset_id: str) -> bool:
        return not self._whitelist or asset_id in self._whitelist

    def create_position(
        self,
        owner: str,
        asset_id: str,
        amount_wei: int,
        initial_price_wei: int,
        drop_bps: int = 2000,
        floor_bps: int = 500,
        trigger_kind: int = SPRG_TRIGGER_KIND_BOTH,
        cooldown_sec: Optional[int] = None,
    ) -> Position:
        if not owner or len(owner) < 40:
            raise SPRG_ZeroAddress()
        if amount_wei <= 0:
            raise SPRG_ZeroAmount()
        if drop_bps > SPRG_MAX_DROP_BPS or drop_bps < 0:
            raise SPRG_InvalidDropBps()
        if floor_bps < SPRG_MIN_FLOOR_BPS or floor_bps > SPRG_BPS_DENOM:
            raise SPRG_InvalidFloorBps()
        if not self.is_whitelisted(asset_id):
            raise SPRG_AssetNotWhitelisted()
        cooldown = cooldown_sec if cooldown_sec is not None else self._default_cooldown_sec
        if cooldown < SPRG_MIN_COOLDOWN_SEC:
            raise SPRG_BelowMinCooldown()
        if cooldown > SPRG_MAX_COOLDOWN_SEC:
            raise SPRG_AboveMaxCooldown()

        now = time.time()
        floor_price_wei = compute_floor_price_wei(initial_price_wei, floor_bps)
        pos = Position(
            position_id=self._next_position_id(),
            owner=to_checksum_address(owner),
            asset_id=asset_id,
            amount_wei=amount_wei,
            high_water_mark_wei=initial_price_wei,
            floor_price_wei=floor_price_wei,
            drop_bps=drop_bps,
            floor_bps=floor_bps,
            trigger_kind=trigger_kind,
            status=SPRG_STATUS_ACTIVE,
            created_at=now,
            last_updated_at=now,
            triggered_at=0.0,
            cooldown_until=0.0,
            sold_amount_wei=0,
        )
        self._positions[pos.position_id] = pos
        return pos

    def get_position(self, position_id: str) -> Optional[Position]:
        return self._positions.get(position_id)

    def require_position(self, position_id: str) -> Position:
        p = self.get_position(position_id)
        if not p:
            raise SPRG_PositionNotFound()
        return p

    def update_high_water_mark(self, position_id: str, caller: str, new_price_wei: int) -> Position:
        pos = self.require_position(position_id)
        if caller != self._guardian and caller != pos.owner:
            raise SPRG_GuardianOnly()
        if new_price_wei <= pos.high_water_mark_wei:
            return pos
        pos.high_water_mark_wei = new_price_wei
        pos.floor_price_wei = compute_floor_price_wei(new_price_wei, pos.floor_bps)
        pos.last_updated_at = time.time()
        return pos

    def disable_position(self, position_id: str, caller: str) -> Position:
        pos = self.require_position(position_id)
        if caller != self._guardian and caller != pos.owner:
            raise SPRG_GuardianOnly()
        pos.status = SPRG_STATUS_DISABLED
        pos.last_updated_at = time.time()
        return pos

    def enable_position(self, position_id: str, caller: str) -> Position:
        pos = self.require_position(position_id)
        if caller != self._guardian and caller != pos.owner:
            raise SPRG_GuardianOnly()
        if pos.status != SPRG_STATUS_DISABLED:
            return pos
        pos.status = SPRG_STATUS_ACTIVE
        pos.last_updated_at = time.time()
        return pos

    def check_and_trigger(self, position_id: str, snapshot: Optional[PriceSnapshot] = None) -> Optional[SellOrder]:
        pos = self.require_position(position_id)
        if pos.status != SPRG_STATUS_ACTIVE:
            return None
        now = time.time()
        if pos.cooldown_until > now:
            return None
        snap = snapshot or self._price_feed.get_price(pos.asset_id)
        if not snap:
            return None
        if not should_trigger(pos, snap):
            return None
        pos.status = SPRG_STATUS_TRIGGERED
        pos.triggered_at = now
        pos.cooldown_until = now + self._default_cooldown_sec
        pos.last_updated_at = now
        order = SellOrder(
            order_id=self._next_order_id(),
            position_id=position_id,
            asset_id=pos.asset_id,
            amount_wei=pos.amount_wei,
            executed_price_wei=snap.price_wei,
            executed_at=now,
            status="executed",
        )
        self._sell_orders[order.order_id] = order
        pos.sold_amount_wei = pos.amount_wei
        pos.status = SPRG_STATUS_SOLD
        return order

    def scan_all_positions(self, caller: str) -> List[SellOrder]:
        if caller != self._keeper and caller != self._guardian:
            raise SPRG_NotKeeper()
        executed = []
        for pid in list(self._positions):
            pos = self._positions[pid]
            if pos.status != SPRG_STATUS_ACTIVE:
                continue
            order = self.check_and_trigger(pid)
            if order:
                executed.append(order)
        return executed

    def list_positions(self, owner: Optional[str] = None) -> List[Position]:
        out = list(self._positions.values())
        if owner:
            owner = to_checksum_address(owner)
            out = [p for p in out if p.owner == owner]
        return out

    def list_orders(self, position_id: Optional[str] = None) -> List[SellOrder]:
        out = list(self._sell_orders.values())
        if position_id:
            out = [o for o in out if o.position_id == position_id]
        return out

    def get_config(self) -> Dict[str, Any]:
        return {
            "guardian": self._guardian,
            "treasury": self._treasury,
            "fee_sink": self._fee_sink,
            "keeper": self._keeper,
            "sentinel": self._sentinel,
            "default_cooldown_sec": self._default_cooldown_sec,
            "version": SPRG_VERSION,
        }

    def export_state(self) -> Dict[str, Any]:
        return {
            "positions": {k: v.to_dict() for k, v in self._positions.items()},
            "orders": {k: v.to_dict() for k, v in self._sell_orders.items()},
            "whitelist": list(self._whitelist),
            "config": self.get_config(),
        }

    def load_state(self, data: Dict[str, Any]) -> None:
        self._positions.clear()
        for k, v in data.get("positions", {}).items():
            self._positions[k] = Position.from_dict(v)
        self._sell_orders.clear()
        for k, v in data.get("orders", {}).items():
            self._sell_orders[k] = SellOrder(**{f: v.get(f) for f in ["order_id", "position_id", "asset_id", "amount_wei", "executed_price_wei", "executed_at", "tx_hash", "status"] if f in v})
            o = self._sell_orders[k]
            o.order_id = o.order_id or k
        self._whitelist = set(data.get("whitelist", []))


# -----------------------------------------------------------------------------
# Validation helpers
# ------------------------------------------------------------------------------

def validate_address(s: str) -> bool:
    s = s.replace("0x", "").lower()
    return len(s) == 40 and all(c in "0123456789abcdef" for c in s)


def validate_drop_bps(bps: int) -> bool:
    return 0 <= bps <= SPRG_MAX_DROP_BPS


def validate_floor_bps(bps: int) -> bool:
    return SPRG_MIN_FLOOR_BPS <= bps <= SPRG_BPS_DENOM


# -----------------------------------------------------------------------------
# Serialization and persistence
# ------------------------------------------------------------------------------

def save_engine_state(engine: SpringaEngine, path: Union[str, Path]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(engine.export_state(), f, indent=2)


def load_engine_state(engine: SpringaEngine, path: Union[str, Path]) -> None:
    path = Path(path)
    if not path.exists():
        return
    with open(path) as f:
        engine.load_state(json.load(f))


# -----------------------------------------------------------------------------
# Fee and treasury helpers (for autosell flow)
# ------------------------------------------------------------------------------

def compute_fee_wei(amount_wei: int, fee_bps: int) -> int:
    return (amount_wei * fee_bps) // SPRG_BPS_DENOM


def compute_net_after_fee(amount_wei: int, fee_bps: int) -> int:
    return amount_wei - compute_fee_wei(amount_wei, fee_bps)


# -----------------------------------------------------------------------------
# Event / callback types (for integration)
# ------------------------------------------------------------------------------

TriggerCallback = Callable[[Position, PriceSnapshot, SellOrder], None]


def run_engine_loop(
    engine: SpringaEngine,
    interval_sec: float = 60.0,
    callback: Optional[TriggerCallback] = None,
    stop_flag: Optional[Callable[[], bool]] = None,
) -> None:
    while stop_flag is None or not stop_flag():
        for pos in engine.list_positions():
            if pos.status != SPRG_STATUS_ACTIVE:
                continue
            order = engine.check_and_trigger(pos.position_id)
            if order and callback:
                snap = engine._price_feed.get_price(pos.asset_id)
                callback(pos, snap, order)
        time.sleep(interval_sec)


# -----------------------------------------------------------------------------
# Default instance and factory
# ------------------------------------------------------------------------------

def create_default_engine(
    guardian: Optional[str] = None,
    treasury: Optional[str] = None,
    price_feed: Optional[PriceFeedBase] = None,
) -> SpringaEngine:
    return SpringaEngine(
        guardian=guardian or SPRG_GUARDIAN_ADDRESS,
        treasury=treasury or SPRG_TREASURY_ADDRESS,
        price_feed=price_feed,
    )


# -----------------------------------------------------------------------------
# Hex and wei formatting
# ------------------------------------------------------------------------------

def wei_to_eth(wei: int) -> float:
    return wei / 1e18


def eth_to_wei(eth: float) -> int:
    return int(eth * 1e18)


def format_wei(wei: int) -> str:
    return f"{wei_to_eth(wei):.6f} ETH"


def truncate_address(addr: str, head: int = 8, tail: int = 6) -> str:
    addr = addr.replace("0x", "")
    if len(addr) <= head + tail:
        return "0x" + addr
    return "0x" + addr[:head] + "..." + addr[-tail:]


# -----------------------------------------------------------------------------
# Position summary and reporting
# ------------------------------------------------------------------------------

def position_summary(pos: Position, current_price_wei: Optional[int] = None) -> str:
    drop = ""
    if current_price_wei is not None and pos.high_water_mark_wei > 0:
        bps = compute_drop_bps(pos.high_water_mark_wei, current_price_wei)
        drop = f" | drop_bps={bps}"
    return (
        f"id={pos.position_id[:20]}... owner={truncate_address(pos.owner)} "
        f"asset={pos.asset_id} amount={pos.amount_wei} hwm={pos.high_water_mark_wei} "
        f"floor={pos.floor_price_wei} status={pos.status}{drop}"
    )


def order_summary(order: SellOrder) -> str:
    return (
        f"id={order.order_id[:20]}... pos={order.position_id[:20]}... "
        f"asset={order.asset_id} amount={order.amount_wei} price={order.executed_price_wei} "
        f"at={order.executed_at} status={order.status}"
    )


# -----------------------------------------------------------------------------
# Additional validation and guards
# ------------------------------------------------------------------------------

def require_guardian(engine: SpringaEngine, caller: str) -> None:
    if to_checksum_address(caller) != engine.guardian:
        raise SPRG_GuardianOnly()


def require_keeper(engine: SpringaEngine, caller: str) -> None:
    if to_checksum_address(caller) != engine.keeper and to_checksum_address(caller) != engine.guardian:
        raise SPRG_NotKeeper()


# -----------------------------------------------------------------------------
# Batch operations
# ------------------------------------------------------------------------------

def batch_create_positions(
    engine: SpringaEngine,
    owner: str,
    assets: List[Tuple[str, int, int]],
    drop_bps: int = 2000,
    floor_bps: int = 500,
) -> List[Position]:
    out = []
    for asset_id, amount_wei, initial_price_wei in assets:
        pos = engine.create_position(owner, asset_id, amount_wei, initial_price_wei, drop_bps=drop_bps, floor_bps=floor_bps)
        out.append(pos)
    return out


def batch_check_positions(engine: SpringaEngine, position_ids: List[str]) -> List[Optional[SellOrder]]:
    return [engine.check_and_trigger(pid) for pid in position_ids]


# -----------------------------------------------------------------------------
# Reporting and stats
# ------------------------------------------------------------------------------

def engine_stats(engine: SpringaEngine) -> Dict[str, Any]:
    positions = engine.list_positions()
    orders = engine.list_orders()
    return {
        "position_count": len(positions),
        "order_count": len(orders),
        "active_count": sum(1 for p in positions if p.status == SPRG_STATUS_ACTIVE),
        "sold_count": sum(1 for p in positions if p.status == SPRG_STATUS_SOLD),
        "disabled_count": sum(1 for p in positions if p.status == SPRG_STATUS_DISABLED),
        "total_sold_wei": sum(p.sold_amount_wei for p in positions),
        "config": engine.get_config(),
    }


def position_report(pos: Position, price_feed: Optional[PriceFeedBase] = None) -> Dict[str, Any]:
    out = pos.to_dict()
    if price_feed:
        snap = price_feed.get_price(pos.asset_id)
        if snap:
            out["current_price_wei"] = snap.price_wei
            out["drop_bps_current"] = compute_drop_bps(pos.high_water_mark_wei, snap.price_wei)
            out["would_trigger_drop"] = should_trigger_drop(snap.price_wei, pos.high_water_mark_wei, pos.drop_bps)
            out["would_trigger_floor"] = should_trigger_floor(snap.price_wei, pos.floor_price_wei)
    return out


# -----------------------------------------------------------------------------
# Simulation and backtest helpers
# ------------------------------------------------------------------------------

def simulate_price_path(initial_wei: int, steps: int, drift_bps_per_step: int, vol_bps: int) -> List[int]:
    import random
    path = [initial_wei]
    for _ in range(steps - 1):
        p = path[-1]
        drift = p * drift_bps_per_step // SPRG_BPS_DENOM
        vol = p * vol_bps // SPRG_BPS_DENOM
        p_next = p + drift + random.randint(-vol, vol)
        path.append(max(0, p_next))
    return path


def backtest_position(
    high_wei: int,
    floor_bps: int,
    drop_bps: int,
    price_path: List[int],
    trigger_kind: int = SPRG_TRIGGER_KIND_BOTH,
) -> Optional[int]:
    floor_wei = compute_floor_price_wei(high_wei, floor_bps)
    for i, p in enumerate(price_path):
        if trigger_kind in (SPRG_TRIGGER_KIND_DROP, SPRG_TRIGGER_KIND_BOTH):
            if should_trigger_drop(p, high_wei, drop_bps):
                return i
        if trigger_kind in (SPRG_TRIGGER_KIND_FLOOR, SPRG_TRIGGER_KIND_BOTH):
            if should_trigger_floor(p, floor_wei):
                return i
    return None


# -----------------------------------------------------------------------------
# Cooldown and timing
# ------------------------------------------------------------------------------

def is_in_cooldown(position: Position, now: Optional[float] = None) -> bool:
    now = now or time.time()
    return position.cooldown_until > now


def cooldown_remaining_sec(position: Position, now: Optional[float] = None) -> float:
    now = now or time.time()
    return max(0.0, position.cooldown_until - now)


# -----------------------------------------------------------------------------
# Position filters
# ------------------------------------------------------------------------------

def filter_positions_active(positions: List[Position]) -> List[Position]:
    return [p for p in positions if p.status == SPRG_STATUS_ACTIVE]


def filter_positions_by_asset(positions: List[Position], asset_id: str) -> List[Position]:
    return [p for p in positions if p.asset_id == asset_id]


def filter_positions_near_trigger(
    positions: List[Position],
    price_feed: PriceFeedBase,
    within_bps: int = 500,
) -> List[Position]:
    out = []
    for p in filter_positions_active(positions):
        snap = price_feed.get_price(p.asset_id)
        if not snap:
            continue
        drop_bps = compute_drop_bps(p.high_water_mark_wei, snap.price_wei)
        if drop_bps >= p.drop_bps - within_bps or snap.price_wei <= p.floor_price_wei + (p.floor_price_wei * within_bps // SPRG_BPS_DENOM):
            out.append(p)
    return out


# -----------------------------------------------------------------------------
# Export / import positions
# ------------------------------------------------------------------------------

def export_positions_json(positions: List[Position]) -> str:
    return json.dumps([p.to_dict() for p in positions], indent=2)


def import_positions_from_json(engine: SpringaEngine, data: str, owner: str) -> List[Position]:
    items = json.loads(data)
    out = []
    for d in items:
        pos = engine.create_position(
            owner=owner,
            asset_id=d["asset_id"],
            amount_wei=int(d["amount_wei"]),
            initial_price_wei=int(d.get("high_water_mark_wei", d.get("initial_price_wei", 0))),
            drop_bps=int(d.get("drop_bps", 2000)),
            floor_bps=int(d.get("floor_bps", 500)),
            trigger_kind=int(d.get("trigger_kind", SPRG_TRIGGER_KIND_BOTH)),
        )
        out.append(pos)
    return out


# -----------------------------------------------------------------------------
# Wei and amount parsing
# ------------------------------------------------------------------------------

def parse_wei(s: str) -> int:
    s = s.strip().upper().replace(",", "")
    if s.endswith("ETH"):
        return eth_to_wei(float(s[:-3].strip()))
    if s.endswith("WEI"):
        return int(s[:-3].strip())
    return int(s)


def format_eth(wei: int, decimals: int = 6) -> str:
    return f"{wei_to_eth(wei):.{decimals}f} ETH"


# -----------------------------------------------------------------------------
# Guardian and keeper checks (repeated for clarity)
# ------------------------------------------------------------------------------

def is_guardian(engine: SpringaEngine, addr: str) -> bool:
    return to_checksum_address(addr) == engine.guardian


def is_keeper(engine: SpringaEngine, addr: str) -> bool:
    a = to_checksum_address(addr)
    return a == engine.keeper or a == engine.guardian


# -----------------------------------------------------------------------------
# High-water mark update batch
# ------------------------------------------------------------------------------

def batch_update_high_water_marks(
    engine: SpringaEngine,
    caller: str,
    updates: List[Tuple[str, int]],
) -> List[Position]:
    out = []
    for position_id, new_price_wei in updates:
        try:
            pos = engine.update_high_water_mark(position_id, caller, new_price_wei)
            out.append(pos)
        except Exception:
            pass
    return out


# -----------------------------------------------------------------------------
# Default whitelist seeding
# ------------------------------------------------------------------------------

def seed_default_whitelist(engine: SpringaEngine, asset_ids: Optional[List[str]] = None) -> None:
    default_assets = asset_ids or ["ETH", "WBTC", "USDC", "USDT", "DAI", "WETH"]
    for aid in default_assets:
        engine.add_to_whitelist(aid)


# -----------------------------------------------------------------------------
# Order history and replay
# ------------------------------------------------------------------------------

def orders_for_position(engine: SpringaEngine, position_id: str) -> List[SellOrder]:
    return engine.list_orders(position_id=position_id)


def total_sold_wei_for_position(engine: SpringaEngine, position_id: str) -> int:
    pos = engine.get_position(position_id)
    return pos.sold_amount_wei if pos else 0


# -----------------------------------------------------------------------------
# Position status display
# ------------------------------------------------------------------------------

def status_display(status: int) -> str:
    if status == SPRG_STATUS_ACTIVE:
        return "active"
    if status == SPRG_STATUS_TRIGGERED:
        return "triggered"
    if status == SPRG_STATUS_SOLD:
        return "sold"
    if status == SPRG_STATUS_DISABLED:
        return "disabled"
    if status == SPRG_STATUS_COOLDOWN:
        return "cooldown"
    return "unknown"


def trigger_kind_display(kind: int) -> str:
    if kind == SPRG_TRIGGER_KIND_DROP:
        return "drop"
    if kind == SPRG_TRIGGER_KIND_FLOOR:
        return "floor"
    if kind == SPRG_TRIGGER_KIND_BOTH:
        return "both"
    return "unknown"


# -----------------------------------------------------------------------------
# Config validation
# ------------------------------------------------------------------------------

def validate_engine_config(config: Dict[str, Any]) -> List[str]:
    errs = []
    for key in ("guardian", "treasury", "fee_sink", "keeper", "sentinel"):
        if key not in config:
            continue
        if not validate_address(config[key]):
            errs.append(f"invalid address: {key}")
    if "default_cooldown_sec" in config:
        c = config["default_cooldown_sec"]
        if c < SPRG_MIN_COOLDOWN_SEC or c > SPRG_MAX_COOLDOWN_SEC:
            errs.append("default_cooldown_sec out of range")
    return errs


# -----------------------------------------------------------------------------
# Constants export
# ------------------------------------------------------------------------------

__all__ = [
    "SpringaEngine",
    "Position",
    "PriceSnapshot",
    "SellOrder",
    "PriceFeedBase",
    "MockPriceFeed",
    "create_default_engine",
    "save_engine_state",
    "load_engine_state",
    "to_checksum_address",
    "random_address_40hex",
    "compute_drop_bps",
    "compute_floor_price_wei",
    "should_trigger_drop",
    "should_trigger_floor",
    "should_trigger",
    "SPRG_VERSION",
    "SPRG_GUARDIAN_ADDRESS",
    "SPRG_TREASURY_ADDRESS",
    "SPRG_FEE_SINK_ADDRESS",
    "SPRG_KEEPER_ADDRESS",
    "SPRG_SENTINEL_ADDRESS",
]


# -----------------------------------------------------------------------------
# Event log types (for integration / indexing)
# ------------------------------------------------------------------------------

@dataclass
class PositionCreatedEvent:
    position_id: str
    owner: str
    asset_id: str
    amount_wei: int
    high_water_mark_wei: int
    timestamp: float


@dataclass
class TriggerFiredEvent:
    position_id: str
    order_id: str
    asset_id: str
    executed_price_wei: int
    timestamp: float


def emit_position_created(pos: Position) -> PositionCreatedEvent:
    return PositionCreatedEvent(
        position_id=pos.position_id,
        owner=pos.owner,
        asset_id=pos.asset_id,
        amount_wei=pos.amount_wei,
        high_water_mark_wei=pos.high_water_mark_wei,
        timestamp=pos.created_at,
    )


def emit_trigger_fired(order: SellOrder) -> TriggerFiredEvent:
    return TriggerFiredEvent(
        position_id=order.position_id,
        order_id=order.order_id,
        asset_id=order.asset_id,
        executed_price_wei=order.executed_price_wei,
        timestamp=order.executed_at,
    )


# -----------------------------------------------------------------------------
# Threshold presets
# ------------------------------------------------------------------------------

SPRG_PRESET_CONSERVATIVE = {"drop_bps": 1000, "floor_bps": 800}
SPRG_PRESET_MODERATE = {"drop_bps": 2000, "floor_bps": 500}
SPRG_PRESET_AGGRESSIVE = {"drop_bps": 3500, "floor_bps": 300}


def create_position_with_preset(
    engine: SpringaEngine,
    owner: str,
    asset_id: str,
    amount_wei: int,
    initial_price_wei: int,
    preset: str = "moderate",
) -> Position:
    presets = {"conservative": SPRG_PRESET_CONSERVATIVE, "moderate": SPRG_PRESET_MODERATE, "aggressive": SPRG_PRESET_AGGRESSIVE}
    p = presets.get(preset, SPRG_PRESET_MODERATE)
    return engine.create_position(owner, asset_id, amount_wei, initial_price_wei, drop_bps=p["drop_bps"], floor_bps=p["floor_bps"])


# -----------------------------------------------------------------------------
# Price staleness check
# ------------------------------------------------------------------------------

SPRG_MAX_PRICE_AGE_SEC = 3600


def is_price_stale(snapshot: PriceSnapshot, max_age_sec: float = SPRG_MAX_PRICE_AGE_SEC) -> bool:
    return (time.time() - snapshot.timestamp) > max_age_sec


def require_fresh_price(snapshot: PriceSnapshot, max_age_sec: float = SPRG_MAX_PRICE_AGE_SEC) -> None:
    if is_price_stale(snapshot, max_age_sec):
        raise SPRG_PriceStale()


# -----------------------------------------------------------------------------
# Numeric safety
# ------------------------------------------------------------------------------

def safe_bps_multiply(amount_wei: int, bps: int) -> int:
    return (amount_wei * bps) // SPRG_BPS_DENOM


def clamp_drop_bps(bps: int) -> int:
    return max(0, min(SPRG_MAX_DROP_BPS, bps))


def clamp_floor_bps(bps: int) -> int:
    return max(SPRG_MIN_FLOOR_BPS, min(SPRG_BPS_DENOM, bps))


# -----------------------------------------------------------------------------
# Position comparison and sorting
# ------------------------------------------------------------------------------

def sort_positions_by_created(positions: List[Position], descending: bool = True) -> List[Position]:
    return sorted(positions, key=lambda p: p.created_at, reverse=descending)


def sort_positions_by_drop_risk(
    positions: List[Position],
    price_feed: PriceFeedBase,
    descending: bool = True,
) -> List[Position]:
    def risk(p: Position) -> float:
        snap = price_feed.get_price(p.asset_id)
        if not snap:
            return 0.0
        return compute_drop_bps(p.high_water_mark_wei, snap.price_wei) / SPRG_BPS_DENOM

    return sorted(positions, key=risk, reverse=descending)


# -----------------------------------------------------------------------------
# Export state to file with version
# ------------------------------------------------------------------------------

def export_state_with_meta(engine: SpringaEngine) -> Dict[str, Any]:
    state = engine.export_state()
    state["_meta"] = {"version": SPRG_VERSION, "exported_at": time.time()}
    return state


def load_state_with_meta(engine: SpringaEngine, data: Dict[str, Any]) -> None:
    meta = data.pop("_meta", {})
    engine.load_state(data)


# -----------------------------------------------------------------------------
# Health check
# ------------------------------------------------------------------------------

def engine_health(engine: SpringaEngine) -> Dict[str, Any]:
    config = engine.get_config()
    errs = validate_engine_config(config)
    return {
        "ok": len(errs) == 0,
        "errors": errs,
        "position_count": len(engine.list_positions()),
        "config_keys": list(config.keys()),
    }


# -----------------------------------------------------------------------------
# Address list validation
# ------------------------------------------------------------------------------

def validate_address_list(addrs: List[str]) -> Tuple[List[str], List[str]]:
    valid = []
    invalid = []
    for a in addrs:
        if validate_address(a):
            valid.append(to_checksum_address(a))
        else:
            invalid.append(a)
    return valid, invalid


# -----------------------------------------------------------------------------
# High-water mark from price feed
# ------------------------------------------------------------------------------

def refresh_high_water_marks_from_feed(
    engine: SpringaEngine,
    caller: str,
    price_feed: Optional[PriceFeedBase] = None,
) -> int:
    feed = price_feed or engine._price_feed
    updated = 0
    for pos in filter_positions_active(engine.list_positions()):
        snap = feed.get_price(pos.asset_id)
        if not snap or snap.price_wei <= pos.high_water_mark_wei:
            continue
        try:
            engine.update_high_water_mark(pos.position_id, caller, snap.price_wei)
            updated += 1
        except Exception:
            pass
    return updated


# -----------------------------------------------------------------------------
# Summary tables (text)
# ------------------------------------------------------------------------------

def positions_table(positions: List[Position], price_feed: Optional[PriceFeedBase] = None) -> str:
    lines = ["position_id | owner | asset_id | amount_wei | hwm | floor | status"]
    for p in positions:
        status = status_display(p.status)
        owner_short = truncate_address(p.owner)
        line = f"{p.position_id[:16]}... | {owner_short} | {p.asset_id} | {p.amount_wei} | {p.high_water_mark_wei} | {p.floor_price_wei} | {status}"
        if price_feed:
            snap = price_feed.get_price(p.asset_id)
            if snap:
                drop = compute_drop_bps(p.high_water_mark_wei, snap.price_wei)
                line += f" | drop_bps={drop}"
        lines.append(line)
    return "\n".join(lines)


def orders_table(orders: List[SellOrder]) -> str:
    lines = ["order_id | position_id | asset_id | amount_wei | price_wei | executed_at"]
    for o in orders:
        lines.append(f"{o.order_id[:16]}... | {o.position_id[:16]}... | {o.asset_id} | {o.amount_wei} | {o.executed_price_wei} | {o.executed_at}")
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Idempotent position creation (by external id)
# ------------------------------------------------------------------------------

def get_or_create_position(
    engine: SpringaEngine,
    owner: str,
    asset_id: str,
    amount_wei: int,
    initial_price_wei: int,
    external_id: str,
    drop_bps: int = 2000,
    floor_bps: int = 500,
) -> Position:
    for pos in engine.list_positions(owner=owner):
        if pos.metadata.get("external_id") == external_id:
            return pos
    pos = engine.create_position(owner, asset_id, amount_wei, initial_price_wei, drop_bps=drop_bps, floor_bps=floor_bps)
    pos.metadata["external_id"] = external_id
    return pos


# -----------------------------------------------------------------------------
# Fee calculation for autosell
# ------------------------------------------------------------------------------

SPRG_DEFAULT_FEE_BPS = 30


def compute_autosell_fee(amount_wei: int, fee_bps: int = SPRG_DEFAULT_FEE_BPS) -> int:
    return safe_bps_multiply(amount_wei, fee_bps)


def compute_autosell_net(amount_wei: int, fee_bps: int = SPRG_DEFAULT_FEE_BPS) -> int:
    return amount_wei - compute_autosell_fee(amount_wei, fee_bps)


# -----------------------------------------------------------------------------
# Domain and salt helpers
# ------------------------------------------------------------------------------

def get_domain_hash() -> str:
    return SPRG_DOMAIN_HASH


def get_config_salt() -> int:
    return SPRG_CONFIG_SALT


def get_default_fee_bps() -> int:
    return SPRG_DEFAULT_FEE_BPS


# -----------------------------------------------------------------------------
# Position ID from hash (deterministic)
# ------------------------------------------------------------------------------

def position_id_from_params(owner: str, asset_id: str, created_ts: int) -> str:
    payload = f"{owner}_{asset_id}_{created_ts}"
    return "0x" + hashlib.sha256(payload.encode()).hexdigest()[:32]


# -----------------------------------------------------------------------------
# Batch disable / enable
# ------------------------------------------------------------------------------

def batch_disable_positions(engine: SpringaEngine, caller: str, position_ids: List[str]) -> List[Position]:
    out = []
    for pid in position_ids:
        try:
            pos = engine.disable_position(pid, caller)
            out.append(pos)
        except Exception:
            pass
    return out


def batch_enable_positions(engine: SpringaEngine, caller: str, position_ids: List[str]) -> List[Position]:
    out = []
    for pid in position_ids:
        try:
            pos = engine.enable_position(pid, caller)
            out.append(pos)
        except Exception:
            pass
    return out


# -----------------------------------------------------------------------------
# Snapshot current state for audit
# ------------------------------------------------------------------------------

def audit_snapshot(engine: SpringaEngine) -> Dict[str, Any]:
    positions = [p.to_dict() for p in engine.list_positions()]
    orders = [o.to_dict() for o in engine.list_orders()]
    return {
        "timestamp": time.time(),
        "config": engine.get_config(),
        "positions": positions,
        "orders": orders,
        "whitelist": list(engine._whitelist),
        "stats": engine_stats(engine),
    }


# -----------------------------------------------------------------------------
# Min/max bounds
# ------------------------------------------------------------------------------

def get_min_floor_bps() -> int:
    return SPRG_MIN_FLOOR_BPS


def get_max_drop_bps() -> int:
    return SPRG_MAX_DROP_BPS


def get_min_cooldown_sec() -> int:
    return SPRG_MIN_COOLDOWN_SEC


def get_max_cooldown_sec() -> int:
    return SPRG_MAX_COOLDOWN_SEC


# -----------------------------------------------------------------------------
# Price feed from dict (for testing)
# ------------------------------------------------------------------------------

def mock_feed_from_prices(prices: Dict[str, int]) -> MockPriceFeed:
    return MockPriceFeed(prices=prices)


# -----------------------------------------------------------------------------
# Position from dict (rehydrate without engine)
