"""Resolving a host's credentials through groups and through never-synced rows.

Two shapes of real data that came out with empty usernames and passwords:

- A host that leaves a field empty inherits it from its group, and that group from its parent.
  Reading only the host's own ssh_config dropped every credential set at group level.
- A row created while sync is off has ``id: undefined`` and may carry ``local_id`` only as the
  IndexedDB record key. Newer Termius also links such a config to its identity through the
  ``ssh_config_identities`` table rather than ``ssh_configs.identity``.
"""

import sys
import unittest

sys.path.insert(0, "src")

from termius_export.normalize import adopt_record_key, build_model


class _Undefined:
    """Stands in for ccl_chromium_reader's sentinel for V8 `undefined`.

    Matches the real class on the three behaviours that matter: falsy, unhashable (``__eq__``
    without ``__hash__``), and ``str()`` yielding ``"<Undefined>"``.
    """

    def __bool__(self):
        return False

    def __eq__(self, other):
        return isinstance(other, _Undefined)

    def __repr__(self):
        return "<Undefined>"

    def __str__(self):
        return "<Undefined>"


UNDEFINED = _Undefined()


class _Tables:
    def __init__(self, tables):
        self.tables = tables
        self.counts_before_dedup = {name: len(rows) for name, rows in tables.items()}


class _NoopDecryptor:
    stats = {"decrypted": 0, "plain": 0, "failed": 0}

    def walk(self, node):
        return node


def _model(**tables):
    return build_model(_Tables(tables), _NoopDecryptor())


def _by_label(model):
    return {h.label: h for h in model.hosts}


class AdoptRecordKeyTests(unittest.TestCase):
    def test_an_undefined_id_is_dropped(self):
        row = adopt_record_key({"id": UNDEFINED, "local_id": 7}, 7.0)
        self.assertNotIn("id", row)
        self.assertEqual(row["local_id"], 7)

    def test_a_missing_local_id_comes_from_the_record_key(self):
        """The key arrives as a float: 145.0, not 145."""
        row = adopt_record_key({"label": "x"}, 145.0)
        self.assertEqual(row["local_id"], 145)
        self.assertIsInstance(row["local_id"], int)

    def test_real_ids_are_left_alone(self):
        row = adopt_record_key({"id": 1683407, "local_id": 4}, 99.0)
        self.assertEqual((row["id"], row["local_id"]), (1683407, 4))

    def test_a_boolean_is_not_an_id(self):
        row = adopt_record_key({"id": True}, 3.0)
        self.assertNotIn("id", row)

    def test_integral_float_ids_from_v8_doubles_are_preserved_as_ints(self):
        """V8 serialises integers outside Smi range (and HeapNumbers) as IEEE-754 doubles."""
        row = adopt_record_key({"id": 3_000_000_000.0, "local_id": 4.0}, 99.0)
        self.assertEqual((row["id"], row["local_id"]), (3_000_000_000, 4))
        self.assertIsInstance(row["id"], int)
        self.assertIsInstance(row["local_id"], int)


class GroupInheritanceTests(unittest.TestCase):
    def setUp(self):
        self.model = _model(
            keys=[
                {
                    "id": 1,
                    "label": "lab",
                    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
                }
            ],
            ssh_identities=[
                {"id": 10, "username": "root", "ssh_key": {"id": 1}},
                {"id": 11, "username": "admin", "password": "group-secret"},
                {"id": 12, "username": "bob", "password": ""},
            ],
            ssh_configs=[
                {"id": 20, "identity": {"id": 10}, "port": 2222},
                {"id": 21, "identity": {"id": 11}},
                {"id": 22},
                {"id": 23, "identity": {"id": 12}},
            ],
            groups=[
                {"id": 30, "label": "Clients", "ssh_config": {"id": 21}},
                {"id": 31, "label": "Acme", "parent_group": {"id": 30}, "ssh_config": {"id": 22}},
                {"id": 32, "label": "Lab", "ssh_config": {"id": 20}},
            ],
            hosts=[
                {"id": 40, "label": "inherits-all", "address": "192.0.2.1", "group": {"id": 31}},
                {
                    "id": 41,
                    "label": "own-user",
                    "address": "192.0.2.2",
                    "group": {"id": 31},
                    "ssh_config": {"id": 23},
                },
                {"id": 42, "label": "lab-node", "address": "192.0.2.3", "group": {"id": 32}},
                {"id": 43, "label": "ungrouped", "address": "192.0.2.4"},
            ],
        )
        self.hosts = _by_label(self.model)

    def test_credentials_come_from_the_nearest_group_that_sets_them(self):
        """Acme sets nothing, so its parent Clients supplies both."""
        h = self.hosts["inherits-all"]
        self.assertEqual((h.username, h.password), ("admin", "group-secret"))

    def test_a_host_value_wins_and_an_empty_one_inherits(self):
        h = self.hosts["own-user"]
        self.assertEqual((h.username, h.password), ("bob", "group-secret"))

    def test_key_and_port_are_inherited(self):
        h = self.hosts["lab-node"]
        self.assertEqual((h.username, h.port), ("root", 2222))
        self.assertIsNotNone(h.key)
        self.assertTrue(h.key.linked, "a key reached through a group is not an orphan")

    def test_the_group_is_the_full_path(self):
        self.assertEqual(self.hosts["inherits-all"].group, "Clients/Acme")
        self.assertEqual(self.hosts["lab-node"].group, "Lab")
        self.assertEqual(self.hosts["ungrouped"].group, "")

    def test_a_parent_cycle_terminates(self):
        model = _model(
            groups=[
                {"id": 1, "label": "A", "parent_group": {"id": 2}},
                {"id": 2, "label": "B", "parent_group": {"id": 1}},
            ],
            hosts=[{"id": 9, "label": "h", "address": "192.0.2.9", "group": {"id": 1}}],
        )
        self.assertEqual(model.hosts[0].group, "B/A")


class NeverSyncedRowTests(unittest.TestCase):
    """Shapes observed on a real profile in which 35 of 146 hosts had never synced."""

    def _rows(self, rows):
        return [adopt_record_key(dict(value), key) for key, value in rows]

    def test_a_local_only_host_resolves_through_ssh_config_identities(self):
        model = _model(
            hosts=self._rows(
                [
                    (
                        133.0,
                        {
                            "label": "local-only",
                            "address": "192.0.2.10",
                            "ssh_config": {"id": UNDEFINED, "local_id": 132},
                        },
                    )
                ]
            ),
            ssh_configs=self._rows([(132.0, {"id": UNDEFINED})]),
            ssh_identities=self._rows([(137.0, {"id": UNDEFINED, "username": "ops", "password": "local-secret"})]),
            ssh_config_identities=self._rows(
                [
                    (
                        131.0,
                        {
                            "ssh_config": {"id": UNDEFINED, "local_id": 132},
                            "identity": {"id": UNDEFINED, "local_id": 137},
                        },
                    )
                ]
            ),
        )
        h = model.hosts[0]
        self.assertEqual((h.username, h.password), ("ops", "local-secret"))

    def test_undefined_ids_do_not_make_unrelated_rows_collide(self):
        """Every never-synced row shares the same `undefined` id. Indexed by it, all of them
        would resolve to whichever came last, handing one host another host's login."""
        model = _model(
            hosts=self._rows(
                [
                    (1.0, {"label": "a", "address": "192.0.2.21", "ssh_config": {"local_id": 1}}),
                    (2.0, {"label": "b", "address": "192.0.2.22", "ssh_config": {"local_id": 2}}),
                ]
            ),
            ssh_configs=self._rows(
                [
                    (1.0, {"id": UNDEFINED, "identity": {"id": UNDEFINED, "local_id": 1}}),
                    (2.0, {"id": UNDEFINED, "identity": {"id": UNDEFINED, "local_id": 2}}),
                ]
            ),
            ssh_identities=self._rows(
                [
                    (1.0, {"id": UNDEFINED, "username": "alice"}),
                    (2.0, {"id": UNDEFINED, "username": "bob"}),
                ]
            ),
        )
        users = {h.label: h.username for h in model.hosts}
        self.assertEqual(users, {"a": "alice", "b": "bob"})

    def test_build_model_ignores_undefined_ids_even_without_adopt_record_key(self):
        model = _model(
            hosts=[
                {"id": UNDEFINED, "local_id": 1, "label": "a", "address": "192.0.2.21", "identity": {"local_id": 1.0}},
                {"id": UNDEFINED, "local_id": 2, "label": "b", "address": "192.0.2.22", "identity": {"local_id": 2}},
            ],
            ssh_identities=[
                {"id": UNDEFINED, "local_id": 1, "username": "alice", "password": UNDEFINED},
                {"id": UNDEFINED, "local_id": 2.0, "username": UNDEFINED, "password": "secret"},
            ],
        )
        by_label = _by_label(model)
        self.assertEqual((by_label["a"].username, by_label["a"].password), ("alice", ""))
        self.assertEqual((by_label["b"].username, by_label["b"].password), ("", "secret"))


if __name__ == "__main__":
    unittest.main()
