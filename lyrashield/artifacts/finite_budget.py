"""One bounded financial snapshot: admission is durable before provider work."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import math
import os
import stat
import threading
import weakref
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from pathlib import Path
from typing import Any, Self
from uuid import uuid4

from lyrashield.artifacts.financial_io import FinancialDirectory, transition_lock


GUARD = "_finite_budget_guard"
STAMP = ".finite-budget-activated"
MAX_RECORD_BYTES = 1024 * 1024
MAX_GUARD_BYTES = 16 * 1024
MAX_PENDING = 64
_MAX_INTEGER = 2**63 - 1
_SCALE = 10**10
_FINANCIAL = ("llm_usage", "web_search_usage")
_owners: weakref.WeakValueDictionary[tuple[int, str], BudgetJournal] = weakref.WeakValueDictionary()
_owners_lock = threading.RLock()


class FinancialStateError(RuntimeError):
    """The allowance cannot safely authorize another paid request."""


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _hash_usage(record: dict[str, Any]) -> str:
    return hashlib.sha256(
        _encoded({key: record[key] for key in _FINANCIAL if key in record})
    ).hexdigest()


def _integer(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _MAX_INTEGER


def _units(amount: float, *, ceiling: bool = True) -> int:
    if isinstance(amount, bool) or not math.isfinite(amount) or amount < 0:
        raise FinancialStateError("invalid financial amount")
    units = int(
        (Decimal(str(amount)) * _SCALE).to_integral_value(
            rounding=ROUND_CEILING if ceiling else ROUND_FLOOR
        )
    )
    if not _integer(units):
        raise FinancialStateError("financial amount exceeds its bound")
    return units


def _decode(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate financial JSON key")
            result[key] = value
        return result

    data = json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
    )
    if not isinstance(data, dict):
        raise FinancialStateError("financial record must be an object")
    return data


def observation_key(model: str | None, response_id: str | None) -> str | None:
    if not response_id:
        return None
    # Response IDs retain the ledger's run-scoped identity across route aliases.
    del model
    return hashlib.sha256(response_id.encode()).hexdigest()


class BudgetJournal:
    """Exclusive process owner with bounded pending IDs and snapshot CAS."""

    def __init__(self, run_dir: Path, record: dict[str, Any], limit: float | None):
        self.path = run_dir.absolute()
        self.pid = os.getpid()
        self._lock = threading.RLock()
        self._stamp_fd = -1
        self._poisoned = False
        self._dispatched: set[str] = set()
        self._directory: FinancialDirectory | None = None
        try:
            self._directory = FinancialDirectory(self.path, create=True)
            with transition_lock(self.path, financial=True):
                existing = self._directory.read("run.json", MAX_RECORD_BYTES)
                current = _decode(existing) if existing is not None else copy.deepcopy(record)
                try:
                    self._stamp_fd = self._directory.open(STAMP, private=True)
                    fresh = False
                except FileNotFoundError:
                    if GUARD in current:
                        raise FinancialStateError("finite guard without activation stamp") from None
                    if limit is None:
                        raise FinancialStateError("finite activation requires a limit") from None
                    self._stamp_fd = self._directory.open(STAMP, create=True, private=True)
                    fresh = True
                self._directory.lock(self._stamp_fd)
                if fresh:
                    self._directory.verify_current_path()
                    stamp = {"v": 1, "run_id": current.get("run_id"), "epoch": uuid4().hex}
                    view = memoryview(_encoded(stamp))
                    while view:
                        written = os.write(self._stamp_fd, view)
                        if written <= 0:
                            raise FinancialStateError("short activation write")  # noqa: TRY301 - release verified handles before propagating failure
                        view = view[written:]
                    os.fsync(self._stamp_fd)
                    self._directory.barrier()
                    usage = current.get("llm_usage") or {}
                    known = float(usage.get("cost") or 0)
                    current[GUARD] = {
                        **stamp,
                        "revision": 0,
                        "next_attempt": 1,
                        "limit_units": _units(
                            float(limit) if limit is not None else 0, ceiling=False
                        ),
                        "known_floor_units": _units(known),
                        "usage_sha256": _hash_usage(current),
                        "pending": [],
                    }
                    self._stamp = stamp
                    self._record = current
                    self._commit(current)
                else:
                    os.lseek(self._stamp_fd, 0, os.SEEK_SET)
                    raw = os.read(self._stamp_fd, 1025)
                    if len(raw) > 1024:
                        raise FinancialStateError("oversized activation stamp")  # noqa: TRY301 - release verified handles before propagating failure
                    self._stamp = _decode(raw)
                    self._record = current
                    self._validate(current)
                if record.get("run_id") != self._stamp.get("run_id"):
                    raise FinancialStateError("foreign financial run identity")  # noqa: TRY301 - release verified handles before propagating failure
                if (
                    limit is not None
                    and _units(limit, ceiling=False) > self._record[GUARD]["limit_units"]
                ):
                    raise FinancialStateError("implicit budget increase refused")  # noqa: TRY301 - release verified handles before propagating failure
                if (
                    limit is not None
                    and _units(limit, ceiling=False) < self._record[GUARD]["limit_units"]
                ):
                    tightened = self.snapshot()
                    tightened[GUARD]["limit_units"] = _units(limit, ceiling=False)
                    tightened[GUARD]["revision"] += 1
                    self._commit(tightened)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            self.close()
            raise FinancialStateError(f"financial state unavailable: {exc}") from exc
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        with contextlib.suppress(OSError):
            self.close()

    def close(self) -> None:
        if self._stamp_fd >= 0:
            os.close(self._stamp_fd)
            self._stamp_fd = -1
        if self._directory is not None:
            self._directory.close()
            self._directory = None

    def _validate(self, record: dict[str, Any]) -> None:
        guard = record.get(GUARD)
        if (
            not isinstance(guard, dict)
            or type(self._stamp.get("v")) is not int
            or self._stamp.get("v") != 1
        ):
            raise FinancialStateError("missing or invalid finite guard")
        if (
            type(guard.get("v")) is not int
            or set(self._stamp) != {"v", "run_id", "epoch"}
            or any(guard.get(key) != self._stamp.get(key) for key in self._stamp)
        ):
            raise FinancialStateError("foreign finite activation")
        if set(guard) - {"observations"} != {
            "v",
            "run_id",
            "epoch",
            "revision",
            "next_attempt",
            "limit_units",
            "known_floor_units",
            "usage_sha256",
            "pending",
        }:
            raise FinancialStateError("unqualified finite guard fields")
        epoch = guard.get("epoch")
        if (
            not isinstance(epoch, str)
            or len(epoch) != 32
            or any(c not in "0123456789abcdef" for c in epoch)
        ):
            raise FinancialStateError("invalid activation epoch")
        if record.get("run_id") != guard.get("run_id") or not isinstance(guard.get("run_id"), str):
            raise FinancialStateError("foreign financial run identity")
        if not guard["run_id"] or len(guard["run_id"]) > 256:
            raise FinancialStateError("invalid financial run identity")
        for key in ("revision", "next_attempt", "limit_units", "known_floor_units"):
            if not _integer(guard.get(key)):
                raise FinancialStateError("invalid finite guard counter")
        if (
            guard["next_attempt"] < 1
            or guard["limit_units"] <= 0
            or guard.get("usage_sha256") != _hash_usage(record)
        ):
            raise FinancialStateError("invalid finite usage snapshot")
        pending = guard.get("pending")
        if (
            not isinstance(pending, list)
            or len(pending) > MAX_PENDING
            or len(_encoded(guard)) > MAX_GUARD_BYTES
        ):
            raise FinancialStateError("finite pending record exceeds bound")
        observations = guard.get("observations", [])
        if not isinstance(observations, list) or len(observations) > MAX_PENDING:
            raise FinancialStateError("observed receipt capacity exceeded")
        seen = set()
        for observed in observations:
            if (
                not isinstance(observed, dict)
                or set(observed)
                not in ({"key", "cost_units", "settled"}, {"key", "floor_credit_units", "settled"})
                or not isinstance(observed["key"], str)
                or len(observed["key"]) != 64
                or any(c not in "0123456789abcdef" for c in observed["key"])
                or observed["key"] in seen
                or not _integer(observed.get("floor_credit_units", observed.get("cost_units")))
                or observed.get("floor_credit_units", 0) > guard["known_floor_units"]
                or type(observed["settled"]) is not bool
            ):
                raise FinancialStateError("invalid observed receipt")
            seen.add(observed["key"])
        ids = set()
        for entry in pending:
            if not isinstance(entry, dict) or set(entry) != {"id", "quote_units", "kind"}:
                raise FinancialStateError("invalid pending entry")
            attempt = entry["id"]
            prefix, separator, counter = (
                attempt.partition(":") if isinstance(attempt, str) else ("", "", "")
            )
            if (
                prefix != epoch
                or not separator
                or not counter.isascii()
                or not counter.isdecimal()
                or str(int(counter)) != counter
                or not 0 < int(counter) < guard["next_attempt"]
                or attempt in ids
            ):
                raise FinancialStateError("invalid pending identity")
            if not _integer(entry["quote_units"]) or entry["kind"] not in {"llm", "search"}:
                raise FinancialStateError("invalid pending quote")
            ids.add(attempt)

    def _current(self) -> dict[str, Any]:
        if self._poisoned or self.pid != os.getpid() or self._directory is None:
            raise FinancialStateError("financial owner is closed or uncertain")
        try:
            stamp_fd = self._directory.open(STAMP, private=True)
            try:
                info, owned = os.fstat(stamp_fd), os.fstat(self._stamp_fd)
                if (info.st_dev, info.st_ino) != (owned.st_dev, owned.st_ino):
                    raise FinancialStateError("activation stamp identity changed")
            finally:
                os.close(stamp_fd)
            os.lseek(self._stamp_fd, 0, os.SEEK_SET)
            stamp = os.read(self._stamp_fd, 1025)
            raw = self._directory.read("run.json", MAX_RECORD_BYTES)
            if stamp is None or _decode(stamp) != self._stamp or raw is None:
                raise FinancialStateError("missing financial activation or record")  # noqa: TRY301 - poison owner before propagating
            current = _decode(raw)
            self._validate(current)
            if current[GUARD] != self._record[GUARD]:
                raise FinancialStateError("stale financial owner")  # noqa: TRY301 - poison owner before propagating
        except (OSError, ValueError, TypeError, FinancialStateError) as exc:
            self._poisoned = True
            raise FinancialStateError(f"financial state unavailable: {exc}") from exc
        else:
            return current

    def _commit(self, record: dict[str, Any]) -> None:
        try:
            self._validate(record)
            payload = _encoded(record)
            if len(payload) > MAX_RECORD_BYTES:
                raise FinancialStateError("financial run record exceeds its bound")
            if self._directory is None:
                raise FinancialStateError("financial owner closed")
            self._directory.replace("run.json", payload)
            self._record = copy.deepcopy(record)
        except (OSError, ValueError, TypeError) as exc:
            self._poisoned = True
            raise FinancialStateError(f"financial persist failed: {exc}") from exc

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._current())

    @property
    def limit(self) -> float:
        return float(self._record[GUARD]["limit_units"] / _SCALE)

    @property
    def spent(self) -> float:
        return float(self._record[GUARD]["known_floor_units"] / _SCALE)

    def require_resumable(self) -> None:
        if self.snapshot()[GUARD]["pending"]:
            raise FinancialStateError("pending provider charge prevents paid resume")

    def authorize(self, attempt: str) -> str:
        """One physical submission may consume this durable admission once."""
        with self._lock:
            current = self._current()
            if attempt in self._dispatched or not any(
                entry["id"] == attempt for entry in current[GUARD]["pending"]
            ):
                raise FinancialStateError("missing or consumed durable admission")
            run_id = current[GUARD]["run_id"]
            if not isinstance(run_id, str) or not run_id:
                raise FinancialStateError("durable admission has no run identity")
            self._dispatched.add(attempt)
            return run_id

    def reserve(self, quote: float, *, kind: str = "llm") -> str:
        with self._lock:
            current = self._current()
            guard = current[GUARD]
            amount = _units(quote)
            if (
                len(guard["pending"]) >= MAX_PENDING
                or guard["next_attempt"] >= _MAX_INTEGER
                or guard["revision"] >= _MAX_INTEGER
            ):
                raise FinancialStateError("finite pending capacity exhausted")
            known = max(
                guard["known_floor_units"],
                _units(float(current.get("llm_usage", {}).get("cost") or 0)),
            )
            if (
                known + sum(entry["quote_units"] for entry in guard["pending"]) + amount
                > guard["limit_units"]
            ):
                raise FinancialStateError("next request exceeds finite budget")
            attempt = f"{guard['epoch']}:{guard['next_attempt']}"
            guard["next_attempt"] += 1
            guard["revision"] += 1
            guard["pending"].append({"id": attempt, "quote_units": amount, "kind": kind})
            self._commit(current)
            return attempt

    def settle(
        self, attempt: str, record: dict[str, Any], actual: float, *, observation: str | None = None
    ) -> bool:
        with self._lock:
            current = self._current()
            guard = current[GUARD]
            if not any(entry["id"] == attempt for entry in guard["pending"]):
                prefix, separator, counter = attempt.partition(":")
                if (
                    prefix != guard["epoch"]
                    or not separator
                    or not counter.isascii()
                    or not counter.isdecimal()
                    or str(int(counter)) != counter
                    or not 0 < int(counter) < guard["next_attempt"]
                ):
                    raise FinancialStateError("foreign financial attempt")
                return False
            if record.get(GUARD) != guard:
                raise FinancialStateError("stale financial settlement")
            for key in _FINANCIAL:
                if key in record:
                    current[key] = copy.deepcopy(record[key])
            credit = 0
            if observation is not None:
                matched = next(
                    (
                        entry
                        for entry in guard.get("observations", [])
                        if entry["key"] == observation
                    ),
                    None,
                )
                if matched is None or matched["settled"]:
                    raise FinancialStateError("observed response is missing or already settled")
                # Older receipts did not attribute their actual floor increment.
                # They cannot prove any credit against this settlement.
                credit = matched.get("floor_credit_units", 0)
                matched["settled"] = True
            guard["known_floor_units"] = max(
                guard["known_floor_units"] + max(0, _units(actual) - credit),
                _units(float(current.get("llm_usage", {}).get("cost") or 0)),
            )
            guard["pending"] = [entry for entry in guard["pending"] if entry["id"] != attempt]
            guard["revision"] += 1
            guard["usage_sha256"] = _hash_usage(current)
            for key in ("seq", "turn_count"):
                current[key] = max(current.get(key, 0), record.get(key, 0))
            self._commit(current)
            self._dispatched.discard(attempt)
            return True

    def checkpoint_known(
        self,
        record: dict[str, Any],
        *,
        observed: tuple[str, float] | None = None,
        settled_observation: str | None = None,
    ) -> dict[str, Any]:
        """Persist observed known usage without reconciling any pending ID."""
        with self._lock:
            current = self._current()
            if record.get(GUARD) != current[GUARD]:
                raise FinancialStateError("stale financial checkpoint")
            prior_floor = current[GUARD]["known_floor_units"]
            new_observation = None
            if observed is not None:
                entries = current[GUARD].setdefault("observations", [])
                if any(entry["key"] == observed[0] for entry in entries):
                    return copy.deepcopy(current)
                if len(entries) >= MAX_PENDING:
                    self._poisoned = True
                    raise FinancialStateError("observed receipt capacity exceeded")
                new_observation = {"key": observed[0], "floor_credit_units": 0, "settled": False}
                entries.append(new_observation)
            if settled_observation is not None:
                for entry in current[GUARD].get("observations", []):
                    if entry["key"] == settled_observation:
                        entry["settled"] = True
            for key in _FINANCIAL:
                if key in record:
                    current[key] = copy.deepcopy(record[key])
            current[GUARD]["known_floor_units"] = max(
                current[GUARD]["known_floor_units"],
                _units(float(current.get("llm_usage", {}).get("cost") or 0)),
            )
            if new_observation is not None and observed is not None:
                new_observation["floor_credit_units"] = min(
                    _units(observed[1]), current[GUARD]["known_floor_units"] - prior_floor
                )
            current[GUARD]["usage_sha256"] = _hash_usage(current)
            current[GUARD]["revision"] += 1
            self._commit(current)
            return self.snapshot()

    def observation(self, key: str | None) -> dict[str, Any] | None:
        if key is None:
            return None
        return next(
            (
                entry
                for entry in self.snapshot()[GUARD].get("observations", [])
                if entry["key"] == key
            ),
            None,
        )

    def write_projection(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            current = self._current()
            if record.get(GUARD) != current[GUARD] or _hash_usage(record) != _hash_usage(current):
                raise FinancialStateError("stale financial projection")
            self._commit(copy.deepcopy(record))
            return self.snapshot()

    def restore_projection(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            current = self._current()
            if record.get("run_id") != current.get("run_id"):
                raise FinancialStateError("foreign projection identity")
            restored = copy.deepcopy(record)
            for key in ("schema_version", "evidence_format"):
                if key in current:
                    restored[key] = current[key]
            for key in (*_FINANCIAL, GUARD):
                if key in current:
                    restored[key] = copy.deepcopy(current[key])
                else:
                    restored.pop(key, None)
            for key in ("seq", "turn_count"):
                restored[key] = max(current.get(key, 0), record.get(key, 0))
            self._commit(restored)
            return self.snapshot()

    def restore_limit(self, limit: float | None) -> None:
        """Ordinary options may tighten, never widen saved financial authority."""
        if limit is None:
            return
        with self._lock:
            current = self._current()
            amount = _units(limit, ceiling=False)
            if amount > current[GUARD]["limit_units"]:
                raise FinancialStateError("implicit budget increase refused")
            if amount < current[GUARD]["limit_units"]:
                current[GUARD]["limit_units"] = amount
                current[GUARD]["revision"] += 1
                self._commit(current)

    def increase_limit(self, limit: float) -> None:
        with self._lock:
            current = self._current()
            amount = _units(limit, ceiling=False)
            if amount < current[GUARD]["limit_units"]:
                raise FinancialStateError("budget increase cannot decrease limit")
            current[GUARD]["limit_units"] = amount
            current[GUARD]["revision"] += 1
            self._commit(current)


def active_journal(run_dir: Path) -> BudgetJournal | None:
    with _owners_lock:
        owner = _owners.get((os.getpid(), str(run_dir.absolute())))
        return owner if owner is not None and owner._directory is not None else None


def own_journal(run_dir: Path, record: dict[str, Any], limit: float | None) -> BudgetJournal:
    directory = FinancialDirectory(run_dir, create=True)
    directory.close()
    with transition_lock(run_dir, financial=True), _owners_lock:
        owner = active_journal(run_dir)
        if owner is None:
            owner = BudgetJournal(run_dir, record, limit)
            try:
                owner.require_resumable()
            except BaseException:
                owner.close()
                raise
            _owners[(os.getpid(), str(run_dir.absolute()))] = owner
        owner.restore_limit(limit)
        return owner


def protected_run(run_dir: Path, record: dict[str, Any] | None = None) -> bool:
    if GUARD in (record or {}) or os.path.lexists(run_dir / STAMP):
        return True
    # An initializer's candidate need not carry the existing private guard.
    # Inspect the bounded on-disk record before deciding this is a legacy write.
    try:
        fd = os.open(run_dir / "run.json", os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise FinancialStateError("run record is not regular")
            raw = source.read(MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES:
            raise FinancialStateError("cannot classify oversized run record")
        return GUARD in _decode(raw)
    except FileNotFoundError:
        return False
    except (OSError, ValueError, TypeError) as exc:
        raise FinancialStateError(f"cannot classify financial state: {exc}") from exc


def guarded_write(run_dir: Path, record: dict[str, Any], *, restore: bool = False) -> bool:
    with transition_lock(run_dir, financial=protected_run(run_dir, record)):
        if not protected_run(run_dir, record):
            return False
        owner = active_journal(run_dir)
        temporary = owner is None
        if owner is None:
            owner = BudgetJournal(run_dir, record, None)
        try:
            updated = (
                owner.restore_projection(record) if restore else owner.write_projection(record)
            )
            record.clear()
            record.update(updated)
        finally:
            if temporary:
                owner.close()
        return True


def refresh_financial_state(state: Any) -> None:
    """A finding rollback may restore projections, never its old financial epoch."""
    if not protected_run(state.get_run_dir(), state.run_record):
        return
    guarded_write(state.get_run_dir(), state.run_record, restore=True)
    state._hydrate_llm_usage(state.run_record.get("llm_usage"))
    state._save_seq = max(state._save_seq, state.run_record.get("seq", 0))
    state._turn_count = max(state._turn_count, state.run_record.get("turn_count", 0))
