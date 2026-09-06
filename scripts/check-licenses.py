"""Check the retained license set and locked source dependency inventory."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def check():
    inventory = json.loads((ROOT / "third_party/dependencies.json").read_bytes())
    lock_bytes = (ROOT / "Cargo.lock").read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(lock_bytes).hexdigest() != inventory["cargo_lock_sha256"]:
        raise ValueError("Cargo.lock differs from the license inventory")
    locked = {
        (p["name"], p["version"], p["checksum"])
        for p in tomllib.loads(lock_bytes.decode())["package"] if "checksum" in p
    }
    described = {(p["name"], p["version"], p["checksum"]) for p in inventory["all_locked_packages"]}
    if locked != described:
        raise ValueError("Incomplete locked dependency inventory")
    materials = {p["file"]: p["sha256"] for p in inventory["license_files"]}
    actual = {p.relative_to(ROOT).as_posix() for p in (ROOT / "third_party/licenses").glob("*") if p.is_file()}
    if actual != set(materials):
        raise ValueError("License file set differs from inventory")
    for name, expected in materials.items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT / "third_party/licenses") or path.is_symlink():
            raise ValueError("Invalid license path")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("License bytes changed: " + name)
    for package in inventory["packages"] + inventory["components"]:
        if not package["selected_license"] or not package["license_materials"]:
            raise ValueError("Missing selected license: " + package["id"])
        for material in package["license_materials"]:
            if materials.get(material["file"]) != material["sha256"]:
                raise ValueError("Component/license mapping mismatch")
    print(f"PASS: {len(locked)} locked packages; {len(materials)} exact license/notice files")


if __name__ == "__main__":
    check()
