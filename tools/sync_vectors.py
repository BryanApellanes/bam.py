"""Copies the known-answer vectors from a bam.protocol checkout into tests/vectors.

    python tools/sync_vectors.py <path to bam.protocol>

Records the commit they came from in tests/vectors/SOURCE.md. The checkout must have no uncommitted
changes under spec/vectors, so the recorded commit really is what was copied.
"""
import os
import shutil
import subprocess
import sys


def main(source):
    vectors = os.path.join(source, "spec", "vectors")
    if subprocess.run(["git", "-C", source, "status", "--porcelain", "--", "spec/vectors"],
                      capture_output=True, text=True, check=True).stdout.strip():
        raise SystemExit("spec/vectors has uncommitted changes; commit them first.")
    commit = subprocess.run(["git", "-C", source, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "vectors")
    os.makedirs(target, exist_ok=True)
    names = sorted(name for name in os.listdir(vectors) if name.endswith(".json"))
    for name in names:
        with open(os.path.join(vectors, name), "rb") as handle:
            data = handle.read().replace(b"\r\n", b"\n")
        with open(os.path.join(target, name), "wb") as handle:
            handle.write(data)
    with open(os.path.join(target, "SOURCE.md"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Where these files come from\n\n"
                     "Copied from `spec/vectors` in https://github.com/BryanApellanes/bam.protocol at commit\n"
                     "`%s` by `tools/sync_vectors.py`. Do not edit them here.\n\n" % commit
                     + "".join("- `%s`\n" % name for name in names))
    print("copied", len(names), "files from", commit)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
