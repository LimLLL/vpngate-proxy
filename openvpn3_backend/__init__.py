"""Experimental Python access to the official OpenVPN 3 Core C++ library."""

from __future__ import annotations

from typing import Any

__all__ = [
    "OpenVPN3Error",
    "ProfileEvaluation",
    "VPNConnection",
    "evaluate_profile",
    "native_crypto_self_test",
    "native_platform",
    "prepare_profile",
]


def __getattr__(name: str) -> Any:
    # CLI-only measurements must not pay for loading the native SWIG module.
    if name in __all__:
        from . import core

        return getattr(core, name)
    raise AttributeError(name)
