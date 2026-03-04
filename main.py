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


