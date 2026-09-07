#!/usr/bin/env python3
# Derived from packages/agent-runtime/digitalocean/lib/do_api.py (Heron's) at weir main bfc070e, renamed for Wren; the history in these comments is Heron's.
"""Built-by: @projectx.sui - Co-authored-by: Kaela <kaela@projectxprotocol.dev>

Every DigitalOcean API call deploy-droplet.sh makes about a FIREWALL or an IMAGE SLUG, in one
runnable file instead of a heredoc.

Why it is a file. The firewall creation used to be a python heredoc inside the deploy script, and
the one path that mattered most -- "the POST succeeded, the readback did not match, now what" --
could not be run anywhere. Security's N-4 on the second read is exactly what that costs: the
mismatch branch exited before it ever printed the id, so the id never reached the caller, the
rollback trap was armed on the next line with nothing to roll back, and a firewall the deploy
created stayed on the account with nothing written down. A tag-targeted firewall left behind also
applies to the NEXT droplet born with that tag.

As a file with an --api-base seam it is run end to end against a local HTTP server that answers
like DigitalOcean (test/host.test.mjs): created, readback widened by a tag, DELETE observed. No
network, no account, no droplet.

THE SEAM IS BOUNDED. --api-base is accepted only for the real API or for a loopback address, so
this file cannot be pointed at somebody else's host and handed the token.

Subcommands:
  firewall-none   <token_file> <tag>
      refuses if any firewall on the account already targets <tag>. --create's precondition:
      a second firewall on the same tag is a rule set nobody wrote down that applies to the
      droplet this deploy is about to create.
  firewall-create <token_file> <desk_ip> <name> <tag> <matcher_path> [--id-file PATH]
      creates the firewall, records its id (stderr, and --id-file the moment the POST returns),
      reads it back through lib/firewall_match.py, and DELETES it before exiting non-zero if the
      readback does not match or if anything at all goes wrong after it exists.
  firewall-effective <token_file> <tag>
      prints the effective inbound ruleset every firewall on the account applies to <tag>, read
      from the account rather than from one firewall's own echo (step 9).
  image-slug      <token_file> <slug>
      refuses unless <slug> is listed in GET /v2/images?type=distribution.

The token is read from a FILE PATH given as an argv, never from an argv value and never from the
environment; it is never printed.
"""
import importlib.util
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_API_BASE = "https://api.digitalocean.com"


def api_base() -> str:
    base = os.environ.get("WREN_DO_API_BASE", DEFAULT_API_BASE).rstrip("/")
    if base == DEFAULT_API_BASE:
        return base
    # The only other thing this may be pointed at is a loopback stand-in, which is what the test
    # server is. Anything else would mean handing the account token to a host somebody else names.
    # Parsed, not prefix-matched: "http://127.0.0.1:@evil.example.com/" starts with the loopback
    # prefix and resolves to evil.example.com (Security's T-1). The scheme must be http, the host
    # loopback, no userinfo, no path.
    from urllib.parse import urlsplit
    parts = urlsplit(base)
    if (
        parts.scheme == "http"
        and parts.hostname in {"127.0.0.1", "localhost", "::1"}
        and parts.username is None
        and parts.password is None
        and parts.path in ("", "/")
        and not parts.query
        and not parts.fragment
    ):
        return base
    print(
        f"do_api.py: refused - WREN_DO_API_BASE is {base!r}; it may only be {DEFAULT_API_BASE} or a "
        "loopback address. The account token is sent with every call this file makes.",
        file=sys.stderr,
    )
    sys.exit(2)


def read_token(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


def call(token: str, method: str, path: str, body: dict | None = None) -> dict:
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(api_base() + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def load_matcher(path: str):
    spec = importlib.util.spec_from_file_location("firewall_match", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ensure_tag(token: str, tag: str) -> None:
    """Create the tag if it does not exist. 201 on create; a 422 saying it already exists is fine."""
    try:
        call(token, "POST", "/v2/tags", {"name": tag})
        print(f"do_api.py: tag {tag} created", file=sys.stderr)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        if e.code == 422 and "exist" in detail.lower():
            print(f"do_api.py: tag {tag} already exists", file=sys.stderr)
            return
        raise


def firewalls(token: str) -> list[dict]:
    return call(token, "GET", "/v2/firewalls").get("firewalls") or []


# ---------------------------------------------------------------------------
# firewall-none
# ---------------------------------------------------------------------------
def cmd_firewall_none(argv: list[str]) -> int:
    if len(argv) != 2:
        print("do_api.py: usage: firewall-none <token_file> <tag>", file=sys.stderr)
        return 2
    token, tag = read_token(argv[0]), argv[1]
    existing = [fw for fw in firewalls(token) if tag in (fw.get("tags") or [])]
    if existing:
        print(
            f"do_api.py: refused - {len(existing)} firewall(s) on this account already target tag "
            f"{tag}. A second firewall on the same tag is a rule set nobody wrote down that applies "
            "to the droplet this deploy is about to create, and it is also what a rolled-back "
            "deploy leaves behind. Delete it, or run --status first:",
            file=sys.stderr,
        )
        for fw in existing:
            print(f"  {fw.get('id')}  {fw.get('name')}  tags={fw.get('tags')}", file=sys.stderr)
        return 1
    print(f"do_api.py: no firewall on this account targets tag {tag}")
    return 0


# ---------------------------------------------------------------------------
# firewall-create
# ---------------------------------------------------------------------------
def cmd_firewall_create(argv: list[str]) -> int:
    id_file = None
    if "--id-file" in argv:
        index = argv.index("--id-file")
        id_file = argv[index + 1]
        argv = argv[:index] + argv[index + 2 :]
    if len(argv) != 5:
        print(
            "do_api.py: usage: firewall-create <token_file> <desk_ip> <name> <tag> <matcher_path> "
            "[--id-file PATH]",
            file=sys.stderr,
        )
        return 2
    token = read_token(argv[0])
    desk_ip, name, tag, matcher_path = argv[1], argv[2], argv[3], argv[4]

    inbound = [{"protocol": "tcp", "ports": "22", "sources": {"addresses": [desk_ip]}}]
    outbound = [
        {"protocol": "tcp", "ports": "443", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
        {"protocol": "tcp", "ports": "53", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
        {"protocol": "udp", "ports": "53", "destinations": {"addresses": ["0.0.0.0/0", "::/0"]}},
    ]
    # Targeted by TAG, not by droplet id: this is created BEFORE the droplet exists, and the droplet
    # is created carrying the tag, so it is covered from its first second (Security's A1).
    # DigitalOcean refuses a firewall that targets a tag which does not yet exist
    # ("422 tag wren-v2 does not exist", seen on the first real run, 2026-09-05). Tags are
    # free, idempotent to create, and carry no rule of their own; make it first.
    ensure_tag(token, tag)
    body = {"name": f"{name}-fw", "tags": [tag], "inbound_rules": inbound, "outbound_rules": outbound}

    created = call(token, "POST", "/v2/firewalls", body)["firewall"]
    firewall_id = created["id"]

    # THE ID EXISTS FROM HERE. Written down before anything else can fail (Security's N-4): the
    # --id-file is what the deploy's rollback trap reads, so an id this process never returns is
    # still an id the trap can destroy.
    if id_file:
        with open(id_file, "w", encoding="utf-8") as handle:
            handle.write(firewall_id + "\n")
    print(f"do_api.py: firewall {firewall_id} created and recorded before its readback", file=sys.stderr)

    try:
        readback = call(token, "GET", f"/v2/firewalls/{firewall_id}")["firewall"]
        matcher = load_matcher(matcher_path)
        problems = matcher.differences({"inbound_rules": inbound, "outbound_rules": outbound}, readback)
        if tag not in (readback.get("tags") or []):
            problems.append(f"the firewall is not attached to tag {tag}; the droplet would be born outside it")
    except Exception as exc:  # noqa: BLE001 - anything at all after the create must still delete it
        problems = [f"the readback itself failed: {exc}"]

    if not problems:
        print(firewall_id)
        return 0

    print("FIREWALL READBACK MISMATCH", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    # Deleted HERE, inside the call that made it, before this process exits -- not left to a caller
    # that never received the id.
    try:
        call(token, "DELETE", f"/v2/firewalls/{firewall_id}")
        print(f"do_api.py: firewall {firewall_id} deleted; nothing it made is left on the account", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        print(
            f"do_api.py: WARNING - firewall {firewall_id} could NOT be deleted ({exc}); it is still "
            "on this account and it is in the run record. Delete it by hand.",
            file=sys.stderr,
        )
    return 1


# ---------------------------------------------------------------------------
# firewall-effective
# ---------------------------------------------------------------------------
def cmd_firewall_effective(argv: list[str]) -> int:
    if len(argv) != 2:
        print("do_api.py: usage: firewall-effective <token_file> <tag>", file=sys.stderr)
        return 2
    token, tag = read_token(argv[0]), argv[1]
    applying = [fw for fw in firewalls(token) if tag in (fw.get("tags") or [])]
    if not applying:
        print(f"do_api.py: refused - no firewall on this account targets tag {tag}", file=sys.stderr)
        return 1
    print(f"the effective ruleset for tag {tag}, read from the account ({len(applying)} firewall(s)):")
    for fw in applying:
        print(f"  firewall {fw.get('id')} {fw.get('name')}")
        for rule in fw.get("inbound_rules") or []:
            print(f"    inbound  {rule.get('protocol')}/{rule.get('ports')} sources={rule.get('sources')}")
        for rule in fw.get("outbound_rules") or []:
            print(f"    outbound {rule.get('protocol')}/{rule.get('ports')} destinations={rule.get('destinations')}")
    return 0


# ---------------------------------------------------------------------------
# image-slug
# ---------------------------------------------------------------------------
def cmd_image_slug(argv: list[str]) -> int:
    if len(argv) != 2:
        print("do_api.py: usage: image-slug <token_file> <slug>", file=sys.stderr)
        return 2
    token, slug = read_token(argv[0]), argv[1]
    slugs: set[str] = set()
    path = "/v2/images?type=distribution&per_page=200"
    seen = 0
    while path and seen < 20:
        seen += 1
        payload = call(token, "GET", path)
        for image in payload.get("images") or []:
            if image.get("slug"):
                slugs.add(image["slug"])
        nxt = ((payload.get("links") or {}).get("pages") or {}).get("next")
        path = nxt[len(api_base()) :] if nxt and nxt.startswith(api_base()) else None
    if slug not in slugs:
        print(
            f"do_api.py: refused - the image slug {slug} is not listed in this account's own "
            "GET /v2/images?type=distribution. v1's script named a slug its own notes contradicted; "
            "this reads the account rather than trusting the constant.",
            file=sys.stderr,
        )
        return 1
    print(f"do_api.py: image slug {slug} is listed in GET /v2/images?type=distribution")
    return 0


COMMANDS = {
    "firewall-none": cmd_firewall_none,
    "firewall-create": cmd_firewall_create,
    "firewall-effective": cmd_firewall_effective,
    "image-slug": cmd_image_slug,
}


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in COMMANDS:
        print(f"do_api.py: usage: do_api.py <{'|'.join(COMMANDS)}> ...", file=sys.stderr)
        return 2
    try:
        return COMMANDS[argv[1]](argv[2:])
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        print(f"do_api.py: the API refused: {exc.code} {detail}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"do_api.py: the call failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
