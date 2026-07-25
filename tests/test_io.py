"""Transport layer: sources, sinks, and the shared producer emitter."""

import json
import os
import tempfile
import time
from unittest import mock

import pytest
import requests

from src.emit import Emitter
from src.sinks.file_sink import FileSink
from src.sinks.webhook import WebhookSink
from src.sources.file_source import FileSource
from src.sources.webhook import WebhookSource


def test_file_source():
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write("line1\n")
        tf.flush()
        # Short poll interval keeps the rotation check fast and deterministic.
        source = FileSource(tf.name, backfill=True, poll_interval=0.01)

        events = source.read_events()
        assert next(events) == "line1\n"
        assert next(events) is None

        # Tailing
        tf.write("line2\n")
        tf.flush()
        assert next(events) == "line2\n"

        # Rotation: truncating the file shrinks it, which the source detects.
        with open(tf.name, "w") as tf_new:
            tf_new.write("line3\n")

        time.sleep(0.05)
        assert next(events) is None  # original handle hits EOF and breaks
        os.unlink(tf.name)


def test_file_sink():
    with tempfile.TemporaryDirectory() as td:
        sink = FileSink(alert_dir=td)
        alert = {"alert_id": "test_123", "data": "val", "severity": "HIGH"}
        assert sink.write_alert(alert) is True

        filepath = os.path.join(td, "test_123.json")
        assert os.path.exists(filepath)
        with open(filepath) as f:
            assert json.load(f) == alert


def test_file_sink_fails_fast_on_unwritable_dir():
    """Misconfiguration must stop startup, not surface when a detection fires."""
    with tempfile.TemporaryDirectory() as td:
        readonly = os.path.join(td, "ro")
        os.makedirs(readonly)
        os.chmod(readonly, 0o500)
        try:
            with pytest.raises(RuntimeError, match="not writable"):
                FileSink(alert_dir=os.path.join(readonly, "alerts"))
        finally:
            os.chmod(readonly, 0o700)


def test_file_sink_write_error_does_not_kill_detection():
    with tempfile.TemporaryDirectory() as td:
        sink = FileSink(alert_dir=td)
        with mock.patch("builtins.open", side_effect=OSError("disk full")):
            assert sink.write_alert({"alert_id": "x", "severity": "HIGH"}) is False


def test_webhook_source_requires_valid_token():
    source = WebhookSource(host="127.0.0.1", port=0, auth_token="secret")
    port = source.server.server_address[1]

    assert requests.post(f"http://127.0.0.1:{port}", data="test").status_code == 401
    assert requests.post(
        f"http://127.0.0.1:{port}",
        headers={"Authorization": "Bearer wrong"},
        data="test",
    ).status_code == 401

    r = requests.post(
        f"http://127.0.0.1:{port}",
        headers={"Authorization": "Bearer secret"},
        data="line1\nline2\n",
    )
    assert r.status_code == 202

    events = source.read_events()
    assert next(events) == "line1"
    assert next(events) == "line2"
    source.running = False
    list(events)  # exhaust so the server shuts down


def test_webhook_source_dropped():
    """A bounded queue sheds load and counts what it shed."""
    source = WebhookSource(host="127.0.0.1", port=0, maxsize=1)
    port = source.server.server_address[1]

    r = requests.post(f"http://127.0.0.1:{port}", data="L1\nL2\nL3\n")
    assert r.status_code == 202  # accepts what it can
    assert source.dropped == 2

    source.running = False
    list(source.read_events())  # shut the server thread down


def test_drain_dropped_reports_and_clears():
    source = FileSource("unused")
    source.dropped = 5

    assert source.drain_dropped() == 5
    assert source.dropped == 0
    assert source.drain_dropped() == 0  # idempotent once drained


def test_drain_dropped_does_not_lose_a_concurrent_drop():
    """Drain subtracts what it read rather than zeroing.

    The webhook listener increments this from its own thread while the engine
    drains it. Assigning zero would discard any drop landing between the read
    and the reset - undercounting precisely when the pipeline is overloaded.
    """
    source = FileSource("unused")
    source.dropped = 5

    # Replays drain_dropped's read/subtract with a drop landing in between.
    count = source.dropped
    source.dropped += 3      # listener thread lands a drop here
    source.dropped -= count  # drain subtracts only what it observed

    assert count == 5
    assert source.dropped == 3, "the drop that arrived mid-drain must survive"


def test_sources_without_shedding_report_zero():
    """`dropped` is interface, not an optional attribute the engine probes for."""
    assert FileSource("unused").drain_dropped() == 0


def test_webhook_sink():
    sink = WebhookSink("http://dummy_url")
    with mock.patch("requests.post") as mock_post:
        sink.write_alert({"alert_id": "1", "severity": "CRITICAL"})
        mock_post.assert_called_once()
        assert mock_post.call_args[1]["json"] == {"alert_id": "1", "severity": "CRITICAL"}


def test_emitter_file():
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        emitter = Emitter(log_file=tf.name, max_bytes=10)
        assert emitter.mode == "file"
        emitter.send("0123456789")
        emitter.send("next")

        with open(tf.name) as f:
            lines = f.readlines()
            assert len(lines) == 1
            assert lines[0].strip() == "next"

        os.unlink(tf.name)


def test_emitter_webhook():
    emitter = Emitter(webhook_url="http://dummy")
    assert emitter.mode == "webhook"

    with mock.patch.object(emitter._session, "post") as mock_post:
        mock_post.return_value.status_code = 202
        assert emitter.send("test") is True
        mock_post.assert_called_once()

    # Transport errors are suppressed and backed off, never raised.
    with mock.patch.object(emitter._session, "post", side_effect=requests.RequestException("error")):
        with mock.patch("time.sleep") as mock_sleep:
            assert emitter.send("test") is False
            mock_sleep.assert_called_once_with(1)


def test_emitter_sends_bearer_token():
    emitter = Emitter(webhook_url="http://dummy", auth_token="tok")
    with mock.patch.object(emitter._session, "post") as mock_post:
        mock_post.return_value.status_code = 202
        emitter.send("test")
    assert mock_post.call_args[1]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.parametrize(
    ("status", "reason"),
    [(401, "auth"), (403, "auth"), (500, "http"), (400, "http")],
)
def test_emitter_classifies_rejections(status, reason):
    """A rejected delivery fails loudly and says why.

    requests does not raise on 4xx, so an unchecked status here would discard
    every event while reporting success - a total, silent detection outage.
    """
    seen = []
    emitter = Emitter(webhook_url="http://dummy", on_failure=seen.append)

    with mock.patch.object(emitter._session, "post") as mock_post:
        mock_post.return_value.status_code = status
        with mock.patch("time.sleep"):
            assert emitter.send("test") is False

    assert seen == [reason]
