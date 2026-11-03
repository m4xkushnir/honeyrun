"""Bounded reads of files that belong to the code under test."""
from __future__ import annotations

import os
import stat


def safe_read(path, limit: int = 2_000_000) -> str | None:
    """Text of a regular, non-symlink file, at most `limit` bytes; None for anything else.

    A repo can plant a symlink to /dev/zero or a FIFO where a manifest should be: opening
    those would hang or exhaust memory, so the type is checked before open and the read is capped.
    """
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as f:
            return f.read(limit).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None
