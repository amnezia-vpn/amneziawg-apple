#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
project_file="$repo_root/WireGuard.xcodeproj/project.pbxproj"
source_name="NetworkPathRetentionPolicy.swift"

if ! grep -Fq "/* $source_name */ = {isa = PBXFileReference;" "$project_file"; then
    echo "$source_name is missing from the Xcode project file references" >&2
    exit 1
fi

source_memberships=$(grep -Fc "/* $source_name in Sources */" "$project_file")
if [ "$source_memberships" -ne 4 ]; then
    echo "expected two Xcode build entries and two source-phase memberships for $source_name, got $source_memberships" >&2
    exit 1
fi
