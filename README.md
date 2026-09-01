# TasteCheck — ResonantOS add-on

The TasteCheck frontend craft and ship-gate skill pack, packaged as a
ResonantOS 2.0.0-alpha add-on. One honest line: this add-on **serves the
pack's documents to agents over a local service — it does not run the pack's
checks headless, and it does not fake verdicts.**

The pack itself is [tastecheck](https://github.com/KyaniteLabs/tastecheck)
(MIT, KyaniteLabs) — 19 checkable design-quality gate skills (plus
`tasteroll`, present in the pack but not yet in the upstream README list),
vendored byte-identical under `vendor/` and pinned by hash to upstream commit
`b3cb1155e076feb6176ee210eb62f3b03363337a`. The wrapper adds no dependencies:
Python 3.10+ standard library only.

## Honest surface

TasteCheck's real interface is "an agent reads the skill documents". Its
checks are prose rules executed by the reading agent, plus
browser-injectable auditors (`assets/audit.js`) that need a rendered page.
No headless check runner exists in the pack, so none is pretended here.

- `tastecheck.status` — service version, vendored pack identity (name,
  version, license, upstream commit), skill count, and the honesty note
  (`headless_check_execution: false`).
- `tastecheck.skills` — the catalog: id, name, frontmatter description,
  contract class, file count.
- `tastecheck.skill.get` — one pack document verbatim (home-path redacted):
  `SKILL.md` by default, or a listed `references/` / `assets/` file by exact
  index path.
- `tastecheck.skill.files` — the exact paths `skill.get` accepts per skill.
- `tastecheck.contract` — the skill's machine-readable `contract.json`
  (triggers, exclusions, stop conditions, handoffs), served verbatim.

## Running it

    python3 server.py          # listens on http://127.0.0.1:4894 (the manifest entrypoint)

    curl -s http://127.0.0.1:4894/health
    curl -s -X POST http://127.0.0.1:4894/ -H 'Content-Type: application/json' \
      -d '{"method":"tastecheck.skills"}'
    curl -s -X POST http://127.0.0.1:4894/ -H 'Content-Type: application/json' \
      -d '{"method":"tastecheck.skill.get","params":{"skill":"tastecheck-pass"}}'

Loopback only, no outbound network, no subprocesses, no disk writes, no
capabilities requested, no telemetry. All responses are home-path-redacted.
`TASTECHECK_PORT` is a dev override; the manifest declares 4894.

## Tests

    python3 -m unittest discover -s tests      # wrapper suite
    sh run-validator-check.sh <path-to-2.0.0-alpha-clone>  # manifest vs the real validator

`vendor/` is hash-pinned: the wrapper suite fails loudly on any drift from
the recorded upstream commit. The privacy gate scans the whole tree
(including the vendored skill text) for home paths and personal data.

## License

MIT — see LICENSE. The vendored tastecheck pack is MIT, KyaniteLabs; its
LICENSE ships under `vendor/LICENSE`.
