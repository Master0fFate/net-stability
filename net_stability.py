#!/usr/bin/env python3
"""Compatibility launcher for the packaged Net Stability implementation."""

from __future__ import annotations

import sys
from importlib import import_module

_implementation = import_module("modules.net_stability")

if __name__ == "__main__":
    raise SystemExit(_implementation.main())

sys.modules[__name__] = _implementation
