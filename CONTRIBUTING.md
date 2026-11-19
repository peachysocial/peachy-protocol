# Contributing

Thank you for looking. A few things to know first.

## Before you send a change

Bug reports and proposals go in the issues of
https://github.com/peachysocial/peachy-protocol, and changes go there as pull
requests.

**This repository is a mirror.** The code is developed in Peachy's own
repository and exported here. A change accepted here is applied there and
comes back with the next export, so its history here will not match yours.

**Security issues do not go in issues or pull requests.** Report them
privately, as [SECURITY.md](SECURITY.md) says.

## What a good change looks like

- It keeps every golden table under `mls/fixtures/` passing in every binding,
  or changes the table on purpose and says why. The tables are what the
  official clients agree on; a change to one is a protocol change.
- It passes `cargo test --workspace --all-features` in `mls/`.
- A change to a spec in `docs/` describes the protocol as it is, not as it
  might be. Proposals are welcome as issues.
- A change to `proto/` is not accepted here: the proto subset is generated from
  the service's schema. Open an issue instead.

## Licensing of contributions

Contributions are inbound=outbound: by contributing you license your
contribution under the same license as the files it changes, the MIT License
for code and proto and CC0 1.0 for the specs in `docs/`. No separate agreement
is needed. Only contribute what you have the right to license that way (for
example, work your employer agrees you may contribute).
