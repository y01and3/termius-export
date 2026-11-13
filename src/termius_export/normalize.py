"""Map decrypted Termius tables onto the client-agnostic model.

Termius relations are not inlined objects but ``{"id": ..., "local_id": ...}`` references, and
either key may be the one that resolves — so indexes are built on both.

Reaching a host's key takes three hops::

    host --ssh_config--> ssh_configs --identity--> ssh_identities --ssh_key--> keys

Miss any hop and the username and key both come out empty.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

from .model import (
    AliasAllocator,
    Forward,
    Host,
    Key,
    KnownHost,
    Model,
    Proxy,
    expand_packed_ipv4,
    file_slug,
    is_ssh_safe,
)

if TYPE_CHECKING:
    # Annotations only, and `from __future__ import annotations` keeps them strings at runtime.
    # Importing these eagerly would drag PyNaCl and ccl_chromium_reader into this module and
    # put it out of reach of the test suite, which has to run on a bare checkout. `dec` and
    # `tables` are passed in; nothing here constructs either.
    from .crypto import Decryptor
    from .source import RawTables


def _coerce_id(value) -> int | str | None:
    """Canonicalise a Termius entity id, or return None if ``value`` is not one.

    V8's structured-clone format encodes small integers as int32/uint32 (``int``) and larger or
    heap-allocated numbers — as well as IndexedDB numeric record keys — as IEEE-754 doubles
    (``float``, e.g. ``145.0``). ``undefined`` arrives from ``ccl_chromium_reader`` as a custom
    sentinel object, and ``bool`` is an ``int`` subclass in Python. Normalising integral floats
    to ``int`` makes ``145`` and ``145.0`` name the same entity.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) and value.is_integer() else None
    if isinstance(value, str):
        return value if value else None
    return None


def adopt_record_key(row: dict, record_key) -> dict:
    """Make a raw IndexedDB row resolvable by reference.

    A row created while sync is off has never been given a server ``id``: it is ``undefined``
    rather than absent, and every such row shares that one value. Some of these rows also lack
    ``local_id`` in the value and carry it only as the IndexedDB record key (a float, ``145.0``).
    Drop the meaningless ``id`` and take ``local_id`` from the key, so these rows deduplicate
    and dereference by ``local_id`` like any other.
    """
    if (rid := _coerce_id(row.get("id"))) is not None:
        row["id"] = rid
    else:
        row.pop("id", None)
    if (lid := _coerce_id(row.get("local_id"))) is not None:
        row["local_id"] = lid
    elif (kid := _coerce_id(record_key)) is not None:
        row["local_id"] = kid
    else:
        row.pop("local_id", None)
    return row


def _index(rows: list[dict]) -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for r in rows:
        if (rid := _coerce_id(r.get("id"))) is not None:
            idx[f"id:{rid}"] = r
        if (lid := _coerce_id(r.get("local_id"))) is not None:
            idx[f"lid:{lid}"] = r
    return idx


def _deref(ref, idx: dict[str, dict]) -> dict | None:
    if not ref:
        return None
    if not isinstance(ref, dict):
        cid = _coerce_id(ref)
        return (idx.get(f"id:{cid}") or idx.get(f"lid:{cid}")) if cid is not None else None
    out = None
    if (rid := _coerce_id(ref.get("id"))) is not None:
        out = idx.get(f"id:{rid}")
    if out is None and (lid := _coerce_id(ref.get("local_id"))) is not None:
        out = idx.get(f"lid:{lid}")
    return out


def _entity_key(row: dict | None) -> str:
    if not row:
        return ""
    rid = _coerce_id(row.get("id"))
    lid = _coerce_id(row.get("local_id"))
    return f"{'' if rid is None else rid}/{'' if lid is None else lid}"


def _text(value) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            return ""
        return str(int(value)) if value.is_integer() else str(value)
    # Anything else is a V8 oddball sentinel such as ccl_chromium_reader's _Undefined, whose
    # str() is "<Undefined>".
    return ""


def _proxy_kind(raw: str) -> str:
    low = _text(raw).lower()
    if "socks" in low:
        return "socks5"
    if "http" in low:
        return "http"
    return low or "unknown"


def _forward_type(raw: str) -> str:
    """Termius stores pf_type as "Local Rule" / "Remote Rule" / "Dynamic Rule"."""
    low = _text(raw).lower()
    if low.startswith("remote"):
        return "Remote"
    if low.startswith("dynamic"):
        return "Dynamic"
    return "Local"


def build_model(tables: RawTables, dec: Decryptor, *, source_info: dict | None = None) -> Model:
    decrypted = {name: [dec.walk(row) for row in rows] for name, rows in tables.tables.items()}

    key_rows = decrypted.get("keys", [])
    key_index = _index(key_rows)
    identities = _index(decrypted.get("ssh_identities", []))
    ssh_configs = _index(decrypted.get("ssh_configs", []))
    proxies = _index(decrypted.get("proxies", []))
    groups = _index(decrypted.get("groups", []))

    # Tags live in a join table: tags(label) <- tag_hosts(tag, host) -> hosts
    tag_labels = {_entity_key(t): _text(t.get("label")) for t in decrypted.get("tags", [])}
    tags_by_host: dict[str, list[str]] = {}
    tag_index = _index(decrypted.get("tags", []))
    host_tag_index = _index(decrypted.get("hosts", []))
    for link in decrypted.get("tag_hosts", []):
        tag_row = _deref(link.get("tag"), tag_index)
        host_row = _deref(link.get("host"), host_tag_index)
        label = tag_labels.get(_entity_key(tag_row), "")
        if not label or not host_row:
            continue
        tags_by_host.setdefault(_entity_key(host_row), []).append(label)

    keys_by_entity: dict[str, Key] = {}
    model_keys: list[Key] = []
    for row in key_rows:
        private = _text(row.get("private_key"))
        if not private:
            continue
        label = _text(row.get("label"))
        public = _text(row.get("public_key"))
        entity = _entity_key(row)
        key = Key(
            id=entity,
            label=label,
            # file_slug, not slug: this becomes a path component, and slug answers the ssh
            # question rather than the filename one. See model.file_slug.
            file_base=file_slug(label, f"key_{_coerce_id(row.get('local_id')) or _coerce_id(row.get('id'))}"),
            private_key=private if private.endswith("\n") else private + "\n",
            public_key=f"{public}\n" if public else "",
            passphrase=_text(row.get("passphrase")),
        )
        keys_by_entity[entity] = key
        model_keys.append(key)

    aliases = AliasAllocator()
    hosts: list[Host] = []
    hosts_by_entity: dict[str, Host] = {}

    identity_by_cfg: dict[str, object] = {}
    for link in decrypted.get("ssh_config_identities", []):
        linked_cfg = _deref(link.get("ssh_config"), ssh_configs)
        if linked_cfg and link.get("identity"):
            identity_by_cfg[_entity_key(linked_cfg)] = link["identity"]

    def cfg_identity(c: dict) -> dict | None:
        return _deref(c.get("identity"), identities) or _deref(identity_by_cfg.get(_entity_key(c)), identities)

    def group_chain(row: dict) -> list[dict]:
        """The host's group, then each parent up to the root. Termius nests groups and a host
        inherits whatever its own config leaves unset from the nearest group that sets it."""
        chain: list[dict] = []
        seen: set[str] = set()
        g = _deref(row.get("group"), groups)
        while g is not None and _entity_key(g) not in seen:
            seen.add(_entity_key(g))
            chain.append(g)
            g = _deref(g.get("parent_group"), groups)
        return chain

    for row in decrypted.get("hosts", []):
        cfg = _deref(row.get("ssh_config"), ssh_configs) or {}
        chain = group_chain(row)
        cfgs = [cfg] + [_deref(g.get("ssh_config"), ssh_configs) or {} for g in chain]
        idents = [(cfg_identity(cfg) if cfg else None) or _deref(row.get("identity"), identities)]
        idents += [cfg_identity(c) for c in cfgs[1:] if c]
        idents = [i for i in idents if i]

        # Termius shows an empty host field as inheriting the group's value, so an empty
        # string here means "unset", unlike an empty label (see trap 2 in CLAUDE.md).
        def first(field: str, _idents=idents) -> str:
            return next((_text(i.get(field)) for i in _idents if _text(i.get(field))), "")

        key_row = next((k for k in (_deref(i.get("ssh_key"), key_index) for i in idents) if k), None)
        key = keys_by_entity.get(_entity_key(key_row)) if key_row else None
        if key:
            key.linked = True

        label = _text(row.get("label"))
        # Some hosts store the address as a packed 32-bit integer; expand it before it reaches
        # the alias or any writer. See expand_packed_ipv4.
        address = expand_packed_ipv4(_text(row.get("address")))

        proxy = None
        proxy_row = next((r for r in (_deref(c.get("proxycommand"), proxies) for c in cfgs) if r), None)
        if proxy_row and proxy_row.get("hostname") and proxy_row.get("port"):
            proxy_identity = _deref(proxy_row.get("identity"), identities) or {}
            proxy = Proxy(
                kind=_proxy_kind(proxy_row.get("type")),
                host=_text(proxy_row.get("hostname")),
                port=int(proxy_row.get("port") or 0),
                username=_text(proxy_identity.get("username")),
                password=_text(proxy_identity.get("password")),
            )

        try:
            port = int(next((c.get("port") for c in cfgs if c.get("port")), 22))
        except (TypeError, ValueError):
            port = 22

        host = Host(
            id=_entity_key(row),
            # A host with no name displays as its address in Termius; mirror that here.
            alias=aliases.take(label or address),
            label=label,
            label_was_empty=label == "",
            address=address,
            port=port if port > 0 else 22,
            username=first("username"),
            password=first("password"),
            # Full "/"-separated path ("Clients/Acme"). The leaf alone is ambiguous: two
            # "Servers" groups under different parents would merge into one.
            group="/".join(_text(g.get("label")) for g in reversed(chain) if _text(g.get("label"))),
            key=key,
            proxy=proxy,
            agent_forward=bool(cfg.get("agent_forwarding")),
            tags=sorted(set(tags_by_host.get(_entity_key(row), []))),
        )
        hosts.append(host)
        hosts_by_entity[host.id] = host

    # Second pass, deliberately. Every primary alias is allocated before any ASCII fallback is,
    # so a derived name can never take a name some other host wanted for itself and push that
    # host to "-2". Interleaving the two would make a plain ASCII-named host answer to a
    # suffixed alias because of an unrelated host that happened to be read earlier.
    for host in hosts:
        if not is_ssh_safe(host.alias):
            host.ascii_alias = aliases.take_ascii(host.label, host.address)

    hosts.sort(key=lambda h: h.alias.lower())

    host_index = _index(decrypted.get("hosts", []))
    forwards: list[Forward] = []
    for row in decrypted.get("pf_rules", []):
        owner = _deref(row.get("host"), host_index)
        fwd = Forward(
            label=_text(row.get("label")),
            type=_forward_type(row.get("pf_type")),
            bound_address=_text(row.get("bound_address")) or "127.0.0.1",
            local_port=int(row.get("local_port") or 0),
            target_host=_text(row.get("hostname")),
            target_port=int(row.get("remote_port") or 0),
        )
        forwards.append(fwd)
        owner_host = hosts_by_entity.get(_entity_key(owner))
        if owner_host:
            owner_host.forwards.append(fwd)

    known_hosts = []
    for row in decrypted.get("known_hosts", []):
        hostnames, key = _text(row.get("hostnames")), _text(row.get("key"))
        if not hostnames or not key:
            continue
        known_hosts.append(
            KnownHost(
                hostnames=hostnames,
                key=key,
                marker=_text(row.get("marker")),
                comment=_text(row.get("comment")),
            )
        )

    return Model(
        hosts=hosts,
        keys=model_keys,
        forwards=forwards,
        known_hosts=known_hosts,
        source={
            **(source_info or {}),
            "app": "termius",
            "rows_before_dedup": tables.counts_before_dedup,
            "decrypt_stats": dict(dec.stats),
        },
    )
