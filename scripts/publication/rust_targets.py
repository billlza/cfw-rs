"""The Rust target triples of the shipped programs.

The macOS client and the Windows client are two programs built from one
workspace. A policy gate that evaluates "the shipped dependency graph"
evaluates exactly one program's graph, so each such gate names its target from
this closed set instead of assuming the macOS target.
"""

from __future__ import annotations

MACOS_TARGET = "aarch64-apple-darwin"
WINDOWS_TARGET = "x86_64-pc-windows-msvc"
SHIPPED_TARGETS = (MACOS_TARGET, WINDOWS_TARGET)
