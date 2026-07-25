#!/usr/bin/env python3
"""Validate rendered Kubernetes manifests, not the source files.

A Deployment can reference a ConfigMap or Secret that exists on disk but was
never added to kustomization.yaml. Every file looks correct in isolation, YAML
parses, and the pods land in CreateContainerConfigError. The only artifact
worth checking is the one that actually ships.

Usage:
    kubectl kustomize . | python scripts/validate_manifests.py
"""

import sys

import yaml


def collect(docs):
    """Returns (defined, referenced) name sets keyed by kind."""
    defined = {"ConfigMap": set(), "Secret": set()}
    referenced = {"ConfigMap": set(), "Secret": set()}

    for doc in docs:
        kind = doc.get("kind")
        if kind in defined:
            defined[kind].add(doc["metadata"]["name"])

        pod_spec = doc.get("spec", {}).get("template", {}).get("spec", {})

        for volume in pod_spec.get("volumes") or []:
            if "configMap" in volume:
                referenced["ConfigMap"].add(volume["configMap"]["name"])
            if "secret" in volume:
                referenced["Secret"].add(volume["secret"]["secretName"])

        for container in pod_spec.get("containers") or []:
            for env in container.get("env") or []:
                source = env.get("valueFrom") or {}
                if "configMapKeyRef" in source:
                    referenced["ConfigMap"].add(source["configMapKeyRef"]["name"])
                if "secretKeyRef" in source:
                    referenced["Secret"].add(source["secretKeyRef"]["name"])
            for source in container.get("envFrom") or []:
                if "configMapRef" in source:
                    referenced["ConfigMap"].add(source["configMapRef"]["name"])
                if "secretRef" in source:
                    referenced["Secret"].add(source["secretRef"]["name"])

    return defined, referenced


def main():
    docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
    if not docs:
        print("FAIL: no manifests on stdin", file=sys.stderr)
        return 1

    defined, referenced = collect(docs)
    failures = []
    for kind in defined:
        missing = referenced[kind] - defined[kind]
        if missing:
            failures.append(f"{kind} referenced but never rendered: {sorted(missing)}")

    print(f"rendered {len(docs)} objects")
    for kind in sorted(defined):
        print(f"  {kind}: {len(defined[kind])} defined, {len(referenced[kind])} referenced")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print("OK: every ConfigMap and Secret reference resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
