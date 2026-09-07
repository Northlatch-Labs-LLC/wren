#!/usr/bin/env python3
# Derived from packages/agent-runtime/digitalocean/lib/firewall_match.py (Heron's) at weir main bfc070e, renamed for Wren; the history in these comments is Heron's.
"""Built-by: @projectx.sui - Co-authored-by: Kaela <kaela@projectxprotocol.dev>

Compares the firewall rules deploy-droplet.sh ASKED for against the ones DigitalOcean echoes back.

Why this file exists at all. The create call sends one key inside each rule's source/destination
object:

    {"protocol": "tcp", "ports": "22", "sources": {"addresses": ["203.0.113.4"]}}

and the API echoes back all four:

    {"protocol": "tcp", "ports": "22",
     "sources": {"addresses": ["203.0.113.4"], "droplet_ids": [], "tags": [],
                 "load_balancer_uids": []}}

A `readback["inbound_rules"] != inbound` on the raw objects therefore compares unequal for a
firewall that is exactly right, and the deploy refuses a correct firewall every time (Security's B5
on step 6). It failed closed, which was the right direction -- but paired with no destroy-on-failure
trap it stranded a running, billed droplet.

What is compared, and it is the whole comparison: protocol (case-folded), ports (normalised), the
SORTED address list, AND the three other ways a source or a destination can be widened --
droplet_ids, tags and load_balancer_uids. Those three must be EMPTY in every rule on both sides.

That last sentence is the fix for Security's N-3 on the second read. This module used to drop the
three lists and say so in this docstring, justifying it by a droplet-id list the
create body no longer sends: the firewall is targeted by TAG now, so nothing else
asserted them. The consequence was measured, not reasoned -- an echo of tcp/22 whose `sources`
carried `tags: ["wren-v2"]`, which admits every droplet in the tag to port 22, returned
`differences == []` and read as a clean match. An empty list is the only shape either side may
carry: this deploy asks for addresses and nothing else, so anything else in the echo is a rule
somebody or something else widened.

Both directions are compared as sorted multisets, so an EXTRA rule in the readback is a mismatch
just as loudly as a missing one -- a firewall that admits more than it was asked to admit is the
failure that matters most here.

Usage:
    firewall_match.py <requested.json> <readback.json>
      each file: {"inbound_rules": [...], "outbound_rules": [...]}
      exit 0  - every rule matches, in both directions
      exit 1  - the differences are printed, one per line, and nothing is guessed
      exit 2  - usage error or unreadable/unparsable input
"""
import json
import sys

SIDE_KEY = {"inbound": "sources", "outbound": "destinations"}

# The three lists that widen a source or a destination beyond the addresses that were asked for.
# Each one must be empty in every rule, on both sides of the comparison.
WIDENING_KEYS = ("droplet_ids", "tags", "load_balancer_uids")


def normalise_ports(value: object) -> str:
    """DigitalOcean writes a whole-range port as "0" in a request and "all" in an echo."""
    text = str(value).strip().lower()
    return "all" if text in ("0", "all", "") else text


def widening(rule: dict, direction: str) -> tuple:
    """The non-empty widening lists this rule carries, as a sorted, comparable tuple."""
    side = rule.get(SIDE_KEY[direction]) or {}
    out = []
    for key in WIDENING_KEYS:
        values = tuple(sorted(str(v) for v in (side.get(key) or [])))
        if values:
            out.append((key, values))
    return tuple(out)


def normalise_rule(rule: dict, direction: str) -> tuple:
    side = rule.get(SIDE_KEY[direction]) or {}
    addresses = tuple(sorted(str(a) for a in (side.get("addresses") or [])))
    return (
        str(rule.get("protocol", "")).strip().lower(),
        normalise_ports(rule.get("ports", "")),
        addresses,
        widening(rule, direction),
    )


def describe(rule: tuple) -> str:
    protocol, ports, addresses, extra = rule
    text = f"{protocol}/{ports} from|to [{', '.join(addresses)}]"
    for key, values in extra:
        text += f" {key}=[{', '.join(values)}]"
    return text


def differences(requested: dict, readback: dict) -> list[str]:
    """Every way the two disagree, named. An empty list is the only thing that means 'match'."""
    out: list[str] = []
    for direction in ("inbound", "outbound"):
        key = f"{direction}_rules"
        side = SIDE_KEY[direction]

        # Named before the multiset comparison, because "the firewall has tcp/22 tags=[wren-v2]
        # and it was never asked for" is true but does not say what is actually wrong: a whole tag
        # is admitted on 22. This says it.
        for label, rules in (("asked for", requested.get(key) or []), ("the firewall has", readback.get(key) or [])):
            for rule in rules:
                for widened, values in widening(rule, direction):
                    out.append(
                        f"{direction}: {label} a rule ({str(rule.get('protocol', '')).lower()}/"
                        f"{normalise_ports(rule.get('ports', ''))}) whose {side} carry "
                        f"{widened}=[{', '.join(values)}]; this deploy asks for addresses and "
                        f"nothing else, so every other {side} list must be empty"
                    )

        asked = sorted(normalise_rule(r, direction) for r in (requested.get(key) or []))
        got = sorted(normalise_rule(r, direction) for r in (readback.get(key) or []))
        if asked == got:
            continue
        for rule in asked:
            if got.count(rule) < asked.count(rule):
                out.append(f"{direction}: asked for {describe(rule)} and the firewall does not have it")
        for rule in got:
            if asked.count(rule) < got.count(rule):
                out.append(f"{direction}: the firewall has {describe(rule)} and it was never asked for")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("firewall_match.py: usage: firewall_match.py <requested.json> <readback.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as handle:
            requested = json.load(handle)
        with open(argv[2], encoding="utf-8") as handle:
            readback = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"firewall_match.py: could not read the rules: {exc}", file=sys.stderr)
        return 2

    # A readback is often the whole firewall object; accept either it or the rules alone.
    readback = readback.get("firewall", readback)

    problems = differences(requested, readback)
    if problems:
        print("FIREWALL READBACK MISMATCH", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(
        "firewall readback matches what was asked: protocol, ports and addresses, both directions, "
        "with droplet_ids, tags and load_balancer_uids empty in every rule"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
