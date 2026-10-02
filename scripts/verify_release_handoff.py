"""Reconstruct tagged release data using only independently trusted verifier code."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import tempfile
from pathlib import Path

MAX_ASSET_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def load_trusted_helper(name):
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("trusted_" + name, path)
    if spec is None or spec.loader is None:
        raise ValueError("Missing trusted release verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_handoff(assets, source, commit, epoch):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid authenticated source commit")
    leaves = tuple(assets.iterdir())
    if len(leaves) != 5 or any(p.is_symlink() or not p.is_file() for p in leaves):
        raise ValueError("Release handoff must contain five regular assets")
    sizes = [p.stat().st_size for p in leaves]
    if max(sizes) > MAX_ASSET_BYTES or sum(sizes) > MAX_TOTAL_BYTES:
        raise ValueError("Release handoff exceeds its byte budget")
    evidence_path = assets / "release-evidence.json"
    if evidence_path.stat().st_size > 128 * 1024:
        raise ValueError("Release evidence exceeds its byte budget")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    version = evidence.get("version")
    if not isinstance(version, str) or len(version) > 64 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid stable release version")
    if evidence.get("source_commit") != commit or evidence.get("source_date_epoch") != epoch:
        raise ValueError("Producer evidence differs from authenticated source identity")
    tag = "v" + version
    if evidence.get("tag") != tag:
        raise ValueError("Producer tag differs from release version")
    prepare = load_trusted_helper("prepare_release")
    integrity = load_trusted_helper("verify_release_integrity")
    with tempfile.TemporaryDirectory(prefix="verified-handoff-") as directory:
        root = Path(directory)
        rebuilt = root / "rebuilt"
        prepare.prepare_release(source, rebuilt, version, tag, commit, epoch)
        manifest = integrity.manifest(rebuilt)
        integrity.verify_assets(assets, manifest)
    return {"version": version, "tag": tag, "manifest": manifest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assets", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("commit")
    parser.add_argument("epoch", type=int)
    parser.add_argument("--expected-manifest")
    args = parser.parse_args()
    result = verify_handoff(args.assets, args.source, args.commit, args.epoch)
    if args.expected_manifest and result["manifest"] != json.loads(args.expected_manifest):
        raise ValueError("Promotion bytes differ from the independently verified handoff")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
