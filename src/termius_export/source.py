"""Read Termius's tables straight out of Chromium's IndexedDB (LevelDB).

Termius does not need to be running and no debug port is opened, so a cold backup directory
works just as well as a live profile.

Two traps this module exists to handle:

1. **The same record appears in several generations.** LevelDB accumulates historical writes,
   so one host can show up four times. ``live_only=True`` does *not* help — it filters
   LevelDB-level tombstones, and all of these rows are "live" at that level. The fix is to
   deduplicate on the business key ``id``, keeping the greatest ``updated_at``. Measured on a
   real profile: 52 raw ``hosts`` rows collapse to the 13 hosts the application actually shows.

2. **An object store is not necessarily named after its database.** Take each database's first
   store rather than assuming the names match.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass

from ccl_chromium_reader import ccl_chromium_indexeddb as ccl

from .normalize import adopt_record_key

#: Databases relevant to migration. The rest (history_commands, activities, ...) are not.
WANTED_DATABASES = (
    "hosts",
    "keys",
    "ssh_identities",
    "ssh_configs",
    "proxies",
    "groups",
    "tags",
    "tag_hosts",
    "pf_rules",
    "known_hosts",
    # Newer Termius links a config to its identity here instead of ssh_configs.identity.
    "ssh_config_identities",
)


class IndexedDbNotFound(Exception):
    pass


@dataclass
class RawTables:
    tables: dict[str, list[dict]]
    counts_before_dedup: dict[str, int]

    def get(self, name: str) -> list[dict]:
        return self.tables.get(name, [])


def locate_leveldb(path: str | pathlib.Path) -> pathlib.Path:
    """Accept a Termius data directory, an IndexedDB directory, or the leveldb directory."""
    p = pathlib.Path(path).expanduser()
    candidates = [
        p,
        p / "file__0.indexeddb.leveldb",
        p / "IndexedDB" / "file__0.indexeddb.leveldb",
        p / ".config" / "Termius" / "IndexedDB" / "file__0.indexeddb.leveldb",
    ]
    for c in candidates:
        if (c / "CURRENT").is_file():
            return c
    raise IndexedDbNotFound(
        f"No IndexedDB found under {p}. Point --data-dir at the Termius data directory, e.g.\n"
        "  Linux (snap):  ~/snap/termius-app/current/.config/Termius\n"
        "  Linux (other): ~/.config/Termius\n"
        "  macOS:         ~/Library/Application Support/Termius\n"
        "  Windows:       %APPDATA%\\Termius"
    )


def _dedup_latest(rows: list[dict]) -> list[dict]:
    """Deduplicate by ``id``, keeping the row with the greatest ``updated_at``.

    Falls back to ``local_id`` when ``id`` is absent. Rows with neither are kept as-is rather
    than silently dropped.
    """
    latest: dict[object, dict] = {}
    keyless: list[dict] = []
    for row in rows:
        key = row.get("id")
        if key is None:
            if row.get("local_id") is None:
                keyless.append(row)
                continue
            key = ("local", row.get("local_id"))
        prev = latest.get(key)
        if prev is None or str(row.get("updated_at") or "") >= str(prev.get("updated_at") or ""):
            latest[key] = row
    return list(latest.values()) + keyless


def read_tables(leveldb_path: pathlib.Path, *, keep_all_versions: bool = False) -> RawTables:
    wrapped = ccl.WrappedIndexDB(leveldb_path)
    available = {db.name for db in wrapped.database_ids}

    tables: dict[str, list[dict]] = {}
    before: dict[str, int] = {}
    for name in WANTED_DATABASES:
        if name not in available:
            continue
        db = wrapped[name]
        store_names = list(db.object_store_names)
        if not store_names:
            continue
        rows = [
            adopt_record_key(rec.value, rec.key.value)
            for rec in db[store_names[0]].iterate_records()
            if isinstance(rec.value, dict)
        ]
        before[name] = len(rows)
        tables[name] = rows if keep_all_versions else _dedup_latest(rows)

    return RawTables(tables=tables, counts_before_dedup=before)
