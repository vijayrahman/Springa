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
