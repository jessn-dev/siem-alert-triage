"""The manifest validator exists to catch what unit tests cannot. It still
needs its own tests, or the CI gate is itself unverified."""

import importlib.util
import io
import pathlib

import pytest
import yaml

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "validate_manifests.py"


def _load():
    spec = importlib.util.spec_from_file_location("validate_manifests", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = _load()


def run(manifest_yaml, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(manifest_yaml))
    return validator.main()


def deployment(env_ref=None, volume=None):
    container = {"name": "c"}
    if env_ref:
        container["env"] = [{"name": "T", "valueFrom": env_ref}]
    pod = {"containers": [container]}
    if volume:
        pod["volumes"] = [volume]
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "d"},
        "spec": {"template": {"spec": pod}},
    }


def test_passes_when_every_reference_resolves(monkeypatch):
    docs = [
        {"kind": "Secret", "metadata": {"name": "siem-secrets"}},
        deployment(env_ref={"secretKeyRef": {"name": "siem-secrets", "key": "T"}}),
    ]
    assert run(yaml.dump_all(docs), monkeypatch) == 0


@pytest.mark.parametrize(
    "ref",
    [
        {"secretKeyRef": {"name": "ghost", "key": "T"}},
        {"configMapKeyRef": {"name": "ghost", "key": "T"}},
    ],
)
def test_catches_dangling_env_reference(ref, monkeypatch):
    """Regression: both historical failures were exactly this shape."""
    assert run(yaml.dump_all([deployment(env_ref=ref)]), monkeypatch) == 1


@pytest.mark.parametrize(
    "volume",
    [
        {"name": "v", "configMap": {"name": "ghost"}},
        {"name": "v", "secret": {"secretName": "ghost"}},
    ],
)
def test_catches_dangling_volume_reference(volume, monkeypatch):
    assert run(yaml.dump_all([deployment(volume=volume)]), monkeypatch) == 1


def test_catches_envfrom_references(monkeypatch):
    docs = [{
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "d"},
        "spec": {"template": {"spec": {"containers": [
            {"name": "c", "envFrom": [{"secretRef": {"name": "ghost"}}]}
        ]}}},
    }]
    assert run(yaml.dump_all(docs), monkeypatch) == 1


def test_empty_input_is_a_failure(monkeypatch):
    """An empty render means the build produced nothing, not that all is well."""
    assert run("", monkeypatch) == 1


def test_collect_separates_defined_from_referenced():
    docs = [
        {"kind": "ConfigMap", "metadata": {"name": "cm"}},
        deployment(volume={"name": "v", "configMap": {"name": "cm"}}),
    ]
    defined, referenced = validator.collect(docs)
    assert defined["ConfigMap"] == {"cm"}
    assert referenced["ConfigMap"] == {"cm"}
