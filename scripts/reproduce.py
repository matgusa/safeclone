"""Offline two-build executable reproduction; Python standard library only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-pc-windows-msvc"

def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def read_json(path):
    return json.loads(path.read_bytes())


def run(args, cwd=ROOT, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env).decode("utf-8").strip()


def tree_fingerprint(directory, patterns):
    files = sorted({p for pattern in patterns for p in directory.glob(pattern) if p.is_file()})
    require(bool(files), "Empty build-input directory")
    listing = "".join(f"{sha(p.read_bytes())}  {p.relative_to(directory).as_posix()}\n" for p in files)
    return {"sha256": sha(listing.encode()), "files": len(files), "patterns": patterns}


def host_inputs(sysroot, msvc, sdk):
    """Conservative available-input sets; does not imply every library is linked."""
    return {
        "rustc": run([str(sysroot / "bin/rustc.exe"), "-vV"]),
        "cargo": "\n".join(line for line in run([str(sysroot / "bin/cargo.exe"), "-vV"]).splitlines() if not line.startswith("os: ")),
        "python": sys.version.split()[0],
        "target": TARGET,
        "release_target_cfg": run([str(sysroot / "bin/rustc.exe"), "--print", "cfg", "--target", TARGET, "-C", "opt-level=3", "-C", "debug-assertions=no"]).splitlines(),
        "rust_tools": tree_fingerprint(sysroot / "bin", ["rustc.exe", "cargo.exe", "*.dll"]),
        "rust_libraries": tree_fingerprint(sysroot / f"lib/rustlib/{TARGET}/lib", ["*.rlib", "*.lib", "*.dll"]),
        "rust_link_tools": tree_fingerprint(sysroot / f"lib/rustlib/{TARGET}/bin", ["**/*.exe", "**/*.dll"]),
        "msvc_tools": tree_fingerprint(msvc / "bin/Hostx64/x64", ["link.exe", "dumpbin.exe", "mspdbsrv.exe", "*.dll"]),
        "msvc_libraries": tree_fingerprint(msvc / "lib/x64", ["*.lib"]),
        "sdk_um": tree_fingerprint(sdk / "um/x64", ["*.lib"]),
        "sdk_ucrt": tree_fingerprint(sdk / "ucrt/x64", ["*.lib"]),
        "msvc_toolset": msvc.name,
        "windows_sdk": sdk.name,
    }


def safe_name(name):
    require(bool(re.fullmatch(r"[A-Za-z0-9_.@/-]+", name)), "Invalid archive name")
    require(not name.startswith("/") and not name.endswith("/"), "Absolute/directory entry")
    require(all(x not in ("", ".", "..") for x in name.split("/")), "Traversal/empty component")


def pe_metadata(data):
    require(data[:2] == b"MZ", "Missing MZ")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    require(data[pe:pe + 4] == b"PE\0\0", "Missing PE")
    machine, count, stamp = struct.unpack_from("<HHI", data, pe + 4)
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    require(machine == 0x8664 and struct.unpack_from("<H", data, opt)[0] == 0x20b, "Not native x64 PE32+")
    sections = []
    for i in range(count):
        pos = opt + opt_size + i * 40
        name = data[pos:pos + 8].rstrip(b"\0").decode("ascii")
        size, address, raw_size, offset = struct.unpack_from("<IIII", data, pos + 8)
        sections.append({"name": name, "rva": address, "virtual_size": size, "raw_size": raw_size,
                         "offset": offset, "sha256": sha(data[offset:offset + raw_size])})

    def offset(rva):
        for section in sections:
            if section["rva"] <= rva < section["rva"] + max(section["virtual_size"], section["raw_size"]):
                return section["offset"] + rva - section["rva"]
        raise ValueError("Unmapped PE RVA")

    directories = opt + 112
    imports_rva = struct.unpack_from("<I", data, directories + 8)[0]
    imports = []
    if imports_rva:
        pos = offset(imports_rva)
        while any(data[pos:pos + 20]):
            name_pos = offset(struct.unpack_from("<I", data, pos + 12)[0])
            imports.append(data[name_pos:data.index(b"\0", name_pos)].decode("ascii"))
            pos += 20
    debug_rva, debug_size = struct.unpack_from("<II", data, directories + 6 * 8)
    debug = []
    if debug_rva:
        for pos in range(offset(debug_rva), offset(debug_rva) + debug_size, 28):
            kind, size, _, pointer = struct.unpack_from("<IIII", data, pos + 12)
            item = {"type": kind, "size": size, "sha256": sha(data[pointer:pointer + size])}
            if kind == 2 and data[pointer:pointer + 4] == b"RSDS":
                item.update(guid=str(uuid.UUID(bytes_le=data[pointer + 4:pointer + 20])),
                            age=struct.unpack_from("<I", data, pointer + 20)[0],
                            pdb=data[pointer + 24:pointer + size].rstrip(b"\0").decode("utf-8"))
            debug.append(item)
    security_offset, security_size = struct.unpack_from("<II", data, directories + 4 * 8)
    return {"machine": "AMD64", "format": "PE32+", "timestamp_field": f"{stamp:08x}",
            "timestamp_meaning": "content hash under /Brepro, not wall-clock time",
            "debug": debug, "sections": sections, "imports": sorted(imports),
            "authenticode_table": {"offset": security_offset, "size": security_size}}


def check_crates(dependencies, cargo_home):
    verified = 0
    for package in dependencies["packages"]:
        basename = f"{package['name']}-{package['version']}"
        archives = list((cargo_home / "registry/cache").glob(f"*/{basename}.crate"))
        require(len(archives) == 1, "Ambiguous/missing cached crate")
        archive = archives[0]
        require(sha(archive.read_bytes()) == package["checksum"], "Crate checksum mismatch")
        directory = cargo_home / "registry/src" / archive.parent.name / basename
        expected = set()
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if member.isdir():
                    continue
                require(member.isfile(), "Nonregular crate member")
                prefix, relative = member.name.split("/", 1)
                require(prefix == basename, "Crate root mismatch")
                safe_name(relative)
                expected.add(relative)
                local = directory / relative
                require(not local.is_symlink() and local.read_bytes() == tar.extractfile(member).read(), "Unpacked crate differs from locked archive")
        actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
        require(actual - expected <= {".cargo-ok", ".cargo-checksum.json"}, "Unexpected cached source file")
        verified += 1
    return verified


def build(args):
    frozen = read_json(ROOT / "build/reproducibility.json")
    actual = host_inputs(args.sysroot, args.msvc, args.sdk)
    require(actual == frozen["host_inputs"], "Toolchain/native input fingerprint changed")
    dep = read_json(ROOT / "third_party/dependencies.json")
    manifest = read_json(ROOT / "build/source-files.json")
    paths = sorted(["Cargo.toml", "Cargo.lock"] + [p.relative_to(ROOT).as_posix() for p in (ROOT / "src").rglob("*") if p.is_file()])
    require(paths == sorted(manifest), "Source input set changed")
    source = {}
    for relative in paths:
        path = ROOT / relative
        require(not path.is_symlink() and not any(p.is_symlink() for p in path.parents), "Linked source input")
        source[relative] = path.read_bytes().replace(b"\r\n", b"\n")
        require(sha(source[relative]) == manifest[relative], "Source checksum changed: " + relative)
    require(sha(source["Cargo.lock"]) == dep["cargo_lock_sha256"], "Lockfile drift")
    require(not args.out.is_relative_to(ROOT), "Choose an output directory outside the checkout")
    for parent in [*ROOT.parents, ROOT, *args.out.parents, args.cargo_home.parent]:
        for name in ("config", "config.toml"):
            require(not (parent / ".cargo" / name).exists(), "Ambient Cargo configuration must be reviewed")
    for name in ("config", "config.toml"):
        require(not (args.cargo_home / name).exists(), "Cargo-home configuration must be reviewed")
    count = check_crates(dep, args.cargo_home)
    args.out.mkdir(parents=True, exist_ok=False)
    binaries = []
    build_outputs = []
    for name in ("a", "b"):
        directory = (args.out / name).resolve()
        directory.mkdir()
        for relative, data in source.items():
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        env = {k: v for k, v in os.environ.items() if k.upper() in
               {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "COMSPEC"}}
        env.update(PATH=os.pathsep.join(map(str, [args.sysroot / "bin", args.msvc / "bin/Hostx64/x64", Path(env["SYSTEMROOT"]) / "System32"])),
                   CARGO_HOME=str(args.cargo_home), RUSTC=str(args.sysroot / "bin/rustc.exe"),
                   CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(directory / "build"),
                   LIB=os.pathsep.join(map(str, [args.msvc / "lib/x64", args.sdk / "um/x64", args.sdk / "ucrt/x64"])))
        flags = ["-C", "link-arg=/Brepro", "-C", "linker=" + str(args.msvc / "bin/Hostx64/x64/link.exe")]
        for original, mapped in ((directory, "/safeclone"), (args.cargo_home, "/cargo"), (args.sysroot, "/rust-toolchain")):
            flags.append("--remap-path-prefix=" + str(original) + "=" + mapped)
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
        invocation = [str(args.sysroot / "bin/cargo.exe"), "build", "--release", "--locked", "--offline", "--target", TARGET]
        with (args.out / f"{name}.log").open("wb") as log:
            subprocess.run(invocation, cwd=directory, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        binary = (directory / f"build/{TARGET}/release/safeclone.exe").read_bytes()
        for private in (str(ROOT), str(args.cargo_home), str(args.sysroot), os.environ.get("USERNAME", "")):
            if private:
                require(private.encode() not in binary and private.encode("utf-16le") not in binary, "Local identifier in executable")
        binaries.append(binary)
        outputs = {}
        for output in sorted((directory / "build").glob("**/build/*/output")):
            data = output.read_text(encoding="utf-8").replace(str(directory), "/safeclone").replace(str(args.cargo_home), "/cargo").replace(str(args.sysroot), "/rust-toolchain")
            outputs[output.parent.name] = data
        build_outputs.append(outputs)
        print(f"build_{name}: {len(binary)} bytes SHA256={sha(binary)}", flush=True)
    require(binaries[0] == binaries[1], "Binary reproduction failed")
    require(build_outputs[0] == build_outputs[1], "Build script output differs")
    require(sha(binaries[0]) == frozen["expected_executable_sha256"], "Reference executable mismatch")
    pe = pe_metadata(binaries[0])
    require(any(d["type"] == 16 for d in pe["debug"]), "Missing reproducible PE marker")
    require(pe["authenticode_table"]["size"] == 0, "Unexpected signed executable")
    result = {"source_files": manifest, "cargo_lock_sha256": dep["cargo_lock_sha256"], "inputs": frozen,
              "verified_crate_archives_and_unpacked_sources": count,
              "reproducibility": "PASS: two fresh builds and the reference executable are byte-for-byte identical",
              "binary": {"file": "safeclone.exe", "sha256": sha(binaries[0]), "size": len(binaries[0]), "pe": pe},
              "build_script_outputs": build_outputs[0]}
    (args.out / "BUILD.json").write_bytes(canonical(result))
    (args.out / "safeclone.exe").write_bytes(binaries[0])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sysroot", "msvc", "sdk", "cargo-home", "out"):
        parser.add_argument("--" + name, required=True, type=lambda p: Path(p).resolve())
    build(parser.parse_args())
