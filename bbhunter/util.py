"""Ortak yardimcilar: loglama, paralel calistirma, cikti bicimleme."""

from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, Iterator, TypeVar

T = TypeVar("T")
R = TypeVar("R")

_print_lock = threading.Lock()

# ANSI renkler (Windows 10+ terminalleri destekler)
C_RESET = "\033[0m"
C_DIM = "\033[2m"
C_RED = "\033[31m"
C_GRN = "\033[32m"
C_YEL = "\033[33m"
C_BLU = "\033[34m"
C_CYN = "\033[36m"


def _emit(prefix: str, msg: str, stream=sys.stderr) -> None:
    with _print_lock:
        print(f"{prefix} {msg}{C_RESET}", file=stream, flush=True)


def info(msg: str) -> None:
    _emit(f"{C_BLU}[*]", msg)


def good(msg: str) -> None:
    _emit(f"{C_GRN}[+]", msg)


def warn(msg: str) -> None:
    _emit(f"{C_YEL}[!]", msg)


def err(msg: str) -> None:
    _emit(f"{C_RED}[x]", msg)


def dim(msg: str) -> None:
    _emit(f"{C_DIM}[ ]", msg)


def banner(title: str) -> None:
    line = "=" * (len(title) + 4)
    with _print_lock:
        print(f"\n{C_CYN}{line}\n  {title}\n{line}{C_RESET}", file=sys.stderr, flush=True)


def parallel_map(
    func: Callable[[T], R],
    items: Iterable[T],
    threads: int = 20,
) -> Iterator[R]:
    """items uzerinde func'i thread havuzunda calistirir; sonuclari bitince yield eder."""
    items = list(items)
    if not items:
        return
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futures = {ex.submit(func, it): it for it in items}
        for fut in as_completed(futures):
            try:
                yield fut.result()
            except Exception:
                # tek bir hedefin hatasi tum taramayi durdurmasin
                continue


def dedup_keep_order(items: Iterable[T]) -> list[T]:
    seen: set = set()
    out: list[T] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out
