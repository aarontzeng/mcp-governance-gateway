from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from mcp_governance_gateway.memory_backend import ActorLabels, HttpMemoryBackend, _display_actor


class DisplayActorTests(unittest.TestCase):
    LABELS = {"10000001": "alice@example.com"}

    def test_employee_id_maps_to_email_local_part(self):
        self.assertEqual(_display_actor("10000001", self.LABELS), "alice")

    def test_email_actor_strips_domain(self):
        self.assertEqual(_display_actor("bob@example.com", {}), "bob")

    def test_gateway_and_unknown_pass_through(self):
        self.assertEqual(_display_actor("gateway-demo-project", {}), "gateway-demo-project")
        self.assertEqual(_display_actor("99999999", {}), "99999999")  # unknown employee id, no @, not in map

    def test_none(self):
        self.assertIsNone(_display_actor(None, self.LABELS))


class LabelRecordsTests(unittest.TestCase):
    def _backend(self, labels_map):
        b = HttpMemoryBackend(base_url="http://x", backend_token=None, search_path="/s", save_path="/r")
        b._actor_labels = _FakeLabels(labels_map)
        return b

    def test_memory_concept_and_actor_field_relabeled(self):
        b = self._backend({"10000001": "alice@example.com"})
        mem = {"id": "1", "content": "x", "concepts": ["actor:10000001", "topic:wifi"]}
        out = b._label_memory(mem, b._labels())
        self.assertIn("actor:alice", out["concepts"])
        self.assertIn("topic:wifi", out["concepts"])  # non-actor concepts untouched
        self.assertEqual(out["actor"], "alice")

    def test_lesson_action_actor_relabeled(self):
        b = self._backend({"10000001": "alice@example.com"})
        self.assertEqual(b._label_named({"actor": "10000001"}, b._labels())["actor"], "alice")
        # already-email actor also strips the domain
        self.assertEqual(b._label_named({"actor": "bob@example.com"}, b._labels())["actor"], "bob")


class _FakeLabels:
    def __init__(self, m):
        self._m = m

    def get(self):
        return self._m


class ActorLabelsFileTests(unittest.TestCase):
    def test_loads_and_hot_reloads(self):
        d = tempfile.mkdtemp()
        p = Path(d) / "user-tokens.json"
        p.write_text(json.dumps({"tokens": [{"actor": "10000001", "email": "alice@example.com", "token": "t"}]}))
        al = ActorLabels(str(p))
        self.assertEqual(al.get().get("10000001"), "alice@example.com")
        # absent file -> empty, no crash
        self.assertEqual(ActorLabels(str(Path(d) / "nope.json")).get(), {})
        self.assertEqual(ActorLabels(None).get(), {})

    def test_stored_name_wins_over_email(self):
        d = tempfile.mkdtemp()
        p = Path(d) / "user-tokens.json"
        p.write_text(json.dumps({"tokens": [
            {"actor": "10000001", "email": "a.person@example.com", "name": "A Person", "token": "t"},
        ]}))
        labels = ActorLabels(str(p)).get()
        self.assertEqual(labels["10000001"], "A Person")

    def test_email_is_also_a_key_so_pre_rekey_records_label_the_same(self):
        # Records written before a deployment re-keyed actors to an immutable id
        # carry the raw email as their actor. Both must resolve to one label, or
        # the same person shows up as two contributors either side of that change.
        d = tempfile.mkdtemp()
        p = Path(d) / "user-tokens.json"
        p.write_text(json.dumps({"tokens": [
            {"actor": "10000001", "email": "a.person@example.com", "name": "A Person", "token": "t"},
        ]}))
        labels = ActorLabels(str(p)).get()
        self.assertEqual(labels["a.person@example.com"], "A Person")
        self.assertEqual(_display_actor("10000001", labels), _display_actor("a.person@example.com", labels))

    def test_blank_name_falls_back_to_email(self):
        d = tempfile.mkdtemp()
        p = Path(d) / "user-tokens.json"
        p.write_text(json.dumps({"tokens": [
            {"actor": "10000001", "email": "a.person@example.com", "name": "   ", "token": "t"},
        ]}))
        self.assertEqual(ActorLabels(str(p)).get()["10000001"], "a.person@example.com")


if __name__ == "__main__":
    unittest.main()
