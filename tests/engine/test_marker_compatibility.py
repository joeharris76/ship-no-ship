from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ship_no_ship.engine import dedup, protocol, verdict

pytestmark = [pytest.mark.unit, pytest.mark.fast]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
HISTORY = json.loads((FIXTURES / "pr2769_history.json").read_text(encoding="utf-8"))
GOLDEN = json.loads((FIXTURES / "pr2769_markers.json").read_text(encoding="utf-8"))


def replay_records(protocol: ModuleType, history: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, str]]]:
    replayed = []
    next_id = 1
    for index, entry in enumerate(history["rounds"]):
        paths = sorted(path for path in entry["patches"] if not path.endswith(".md"))
        defects = [
            {
                **{key: item[key] for key in ("severity", "file", "line", "title")},
                "id": f"D{next_id + n}",
                "end_line": None,
            }
            for n, item in enumerate(entry["defects"])
        ]
        next_id += len(defects)
        record = {
            "v": 1,
            "cycle": 1,
            "round": index + 1,
            "kind": protocol.FIRST if index == 0 else protocol.FOLLOW_UP,
            "decision": "SHIP_WITH_FIXES" if defects else "SHIP",
            "head_sha": entry["head_sha"],
            "base_ref": "develop",
            "reviewer": "opus",
            "tier": history["tier"],
            "strikes_after": 0,
            "open_defects": defects,
            "next_id": next_id,
            "patch_digest": protocol.patch_digest(entry["patches"], paths),
            "carried": False,
            "summary": "",
        }
        replayed.append((record, protocol.patch_map(entry["patches"], paths)))
    return replayed


RECORDS = replay_records(protocol, HISTORY)


def test_the_golden_markers_cover_every_round_of_the_fixture() -> None:
    assert len(GOLDEN["protocol_markers"]) == len(RECORDS) == len(HISTORY["rounds"])
    assert len(GOLDEN["finding_markers"]) == sum(len(entry["defects"]) for entry in HISTORY["rounds"])


@pytest.mark.parametrize("index", range(len(HISTORY["rounds"])))
def test_markers_written_by_the_original_engine_decode_to_the_same_record(index: int) -> None:
    record, patches = RECORDS[index]
    assert protocol.decode_marker(f"Review body\n\n{GOLDEN['protocol_markers'][index]}") == {
        **record,
        "patch_map": patches,
    }


@pytest.mark.parametrize("index", range(len(HISTORY["rounds"])))
def test_markers_written_now_keep_the_original_envelope_and_round_trip(index: int) -> None:
    record, patches = RECORDS[index]
    marker = protocol.encode_marker(record, patches)
    golden = GOLDEN["protocol_markers"][index]
    assert marker.split(" ")[:3] == golden.split(" ")[:3] == ["<!--", "oracle-protocol:", "v1"]
    assert marker.endswith(" -->") and golden.endswith(" -->")
    assert protocol.decode_marker(marker) == protocol.decode_marker(golden)


def test_finding_markers_are_byte_identical_to_the_original_engine() -> None:
    findings = [
        verdict.Finding(severity=item["severity"], file=item["file"], line=item["line"], title=item["title"], detail="")
        for entry in HISTORY["rounds"]
        for item in entry["defects"]
    ]
    assert [dedup.marker(finding) for finding in findings] == GOLDEN["finding_markers"]
