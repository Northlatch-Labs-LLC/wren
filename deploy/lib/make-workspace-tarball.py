#!/usr/bin/env python3
"""Built-by: @projectx.sui

The workspace archive Wren's deploy lays over the shared runtime on the host.

Why Python and not tar: the first real --create for Wren (2026-09-06) died on this laptop at
`tar --mtime=...`, a GNU option macOS's bsdtar does not have, after the droplet was already up --
and the rollback destroyed a good host for a laptop-side defect the tests had stubbed past. This
file runs on both tars' behalf and is exercised on this laptop by test/wren.test.mjs.

Reproducible by construction: every regular file under the workspace, sorted by path, with the
mtime, uid, gid and owner names fixed and the mode taken from the file. Two runs over the same tree
produce the same bytes, so the sha256 the deploy prints is a fact about the tree, not about when
the archive was made. Symlinks, sockets and anything that is not a regular file are refused.

Usage: make-workspace-tarball.py <workspace-dir> <out.tgz>
Prints the file count on stdout; refuses on stderr with exit 1.
"""
import gzip
import io
import os
import sys
import tarfile

FIXED_MTIME = 1767225600  # 2026-01-01T00:00:00Z


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("make-workspace-tarball.py: usage: <workspace-dir> <out.tgz>", file=sys.stderr)
        return 1
    root, out = argv[1], argv[2]
    if not os.path.isdir(root):
        print(f"make-workspace-tarball.py: refused - {root} is not a directory", file=sys.stderr)
        return 1
    paths: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                print(f"make-workspace-tarball.py: refused - {full} is not a regular file", file=sys.stderr)
                return 1
            paths.append(os.path.relpath(full, root))
    if not paths:
        print(f"make-workspace-tarball.py: refused - {root} holds no file", file=sys.stderr)
        return 1
    paths.sort()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for rel in paths:
            full = os.path.join(root, rel)
            info = archive.gettarinfo(full, arcname=rel)
            info.mtime = FIXED_MTIME
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if os.access(full, os.X_OK) else 0o644
            with open(full, "rb") as handle:
                archive.addfile(info, handle)
    # gzip with a fixed header (mtime 0, no name) so the compressed bytes are reproducible too.
    with open(out, "wb") as sink:
        with gzip.GzipFile(filename="", mode="wb", fileobj=sink, mtime=0) as gz:
            gz.write(buffer.getvalue())
    print(len(paths))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
