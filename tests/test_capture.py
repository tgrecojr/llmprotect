"""Capture (GUARD_CAPTURE_DIR): every scanned text + verdict lands as JSONL."""

import json
import logging
from dataclasses import replace
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from guard_api.capture import Capture, read_records, record_for
from guard_api.classifier import RiskResult
from guard_api.main import create_app
from test_api import ENDPOINT, SETTINGS, StubClassifier

RESULT = RiskResult(0.7, 1, 3, "cta copy", chunk_scores=(0.1, 0.7, 0.2))


def test_record_shape():
    rec = record_for(
        "hello",
        RESULT,
        call_id="c1",
        text_index=2,
        threshold=0.85,
        config={"chunk_chars": 2000},
        now=datetime(2026, 8, 23, 12, 0, tzinfo=UTC),
    )
    assert rec["ts"] == "2026-08-23T12:00:00+00:00"
    assert rec["call_id"] == "c1"
    assert rec["text_index"] == 2
    assert rec["sha256"].startswith("2cf24dba")  # sha256("hello")
    assert rec["len"] == 5
    assert rec["blocked"] is False
    assert rec["score"] == 0.7
    assert rec["rescore"] is None
    assert rec["chunk_scores"] == [0.1, 0.7, 0.2]
    assert rec["config"] == {"chunk_chars": 2000}
    assert rec["label"] is None
    assert rec["text"] == "hello"


def test_record_carries_rescore_only_when_rescored():
    rec = record_for(
        "x",
        replace(RESULT, score=0.86, rescored=True, rescore=0.4),
        call_id=None,
        text_index=0,
        threshold=0.85,
        config={},
    )
    assert rec["score"] == 0.86
    assert rec["rescore"] == 0.4
    assert rec["blocked"] is False  # the context score decided


def test_capture_appends_one_file_per_day(tmp_path):
    cap = Capture(tmp_path / "guard-capture", {"chunk_chars": 2000})
    for i in range(2):
        cap.write(f"text {i}", RESULT, call_id="c", text_index=i, threshold=0.85)
    files = list((tmp_path / "guard-capture").glob("*.jsonl"))
    assert len(files) == 1
    assert files[0].name == f"{datetime.now(UTC):%Y-%m-%d}.jsonl"
    records = read_records(files[0])
    assert [r["text"] for r in records] == ["text 0", "text 1"]
    assert records[0]["config"] == {"chunk_chars": 2000}


def test_capture_write_failure_is_logged_not_raised(tmp_path, caplog):
    cap = Capture(tmp_path, {})
    cap.directory = tmp_path / "missing"  # never created -> open() fails
    with caplog.at_level(logging.ERROR, logger="guard_api"):
        cap.write("t", RESULT, call_id=None, text_index=0, threshold=0.85)
    assert any("capture write failed" in r.getMessage() for r in caplog.records)


def test_endpoint_captures_every_text_when_enabled(tmp_path):
    settings = replace(SETTINGS, capture_dir=str(tmp_path / "cap"))
    with TestClient(create_app(classifier=StubClassifier(), settings=settings)) as client:
        resp = client.post(
            ENDPOINT,
            json={
                "texts": ["fine", "INJECT payload"],
                "input_type": "request",
                "litellm_call_id": "c9",
            },
        )
    assert resp.json()["action"] == "BLOCKED"
    (path,) = (tmp_path / "cap").glob("*.jsonl")
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert [(r["call_id"], r["text_index"], r["blocked"]) for r in records] == [
        ("c9", 0, False),
        ("c9", 1, True),
    ]
    assert records[1]["text"] == "INJECT payload"
    assert records[1]["config"]["model_id"] == "stub"
    assert records[1]["threshold"] == 0.85


def test_unusable_capture_dir_disables_capture_not_the_guard(tmp_path, caplog):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    settings = replace(SETTINGS, capture_dir=str(blocker / "cap"))
    with caplog.at_level(logging.ERROR, logger="guard_api"):
        app = create_app(classifier=StubClassifier(), settings=settings)
    assert app.state.capture is None
    assert any("capture disabled" in r.getMessage() for r in caplog.records)
    with TestClient(app) as client:
        resp = client.post(ENDPOINT, json={"texts": ["INJECT payload"], "input_type": "request"})
    assert resp.json()["action"] == "BLOCKED"


def test_endpoint_does_not_capture_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = create_app(classifier=StubClassifier(), settings=SETTINGS)
    with TestClient(app) as client:
        client.post(ENDPOINT, json={"texts": ["fine"], "input_type": "request"})
    assert app.state.capture is None
    assert not list(tmp_path.rglob("*.jsonl"))
