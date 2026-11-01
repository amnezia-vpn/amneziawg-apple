#!/usr/bin/env python3
"""Run resolver/model XCTest coverage without building or signing the Go tunnel backend."""
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="awg-srv-tests-") as directory:
    package = Path(directory)
    sources = package / "Sources" / "WireGuardKit"
    sources.mkdir(parents=True)
    for source in (root / "Sources" / "WireGuardKit").glob("*.swift"):
        if source.name != "WireGuardAdapter.swift":
            shutil.copy2(source, sources / source.name)
    shutil.copytree(root / "Sources" / "WireGuardKitC", package / "Sources" / "WireGuardKitC")
    shutil.copytree(root / "Tests" / "WireGuardKitTests", package / "Tests" / "WireGuardKitTests")
    (package / "Package.swift").write_text('''// swift-tools-version:5.5
import PackageDescription
let package = Package(name: "SRVTests", platforms: [.macOS(.v12)], targets: [
    .target(name: "WireGuardKitC", publicHeadersPath: "."),
    .target(name: "WireGuardKit", dependencies: ["WireGuardKitC"]),
    .testTarget(name: "WireGuardKitTests", dependencies: ["WireGuardKit"])
])
''')
    subprocess.run(["swift", "test", "--package-path", str(package), "--filter", "SRVEndpointTests"], check=True)
