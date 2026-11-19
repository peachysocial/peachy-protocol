<!-- SPDX-License-Identifier: MIT -->

# Test vectors

Two sets of published known-answer vectors, each copied unmodified:

- two files of RFC 9420 vectors from the MLS working group's own corpus,
  read by `tests/rfc9420_vectors.rs` (below);
- the X-Wing KEM vectors of draft-connolly-cfrg-xwing-kem-06, read by
  `tests/xwing_vectors.rs` ([X-Wing](#x-wing-draft-06)).

## RFC 9420

**Upstream:** [`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations),
commit `cfd450286d1bfd9cd2519b95c80f9771f94a5b1a`, directory `test-vectors/`.

| File | Bytes | SHA-256 |
|---|---|---|
| `crypto-basics.json` | 20,116 | `17cfcf89af9f51d0f2aa7af77f6f9ec99376a039214b6d42a6f11646b83e8c29` |
| `tree-math.json` | 91,438 | `27f04891f56106593b74b674445f01b845e173953770c084deb2f8cf5592e2fc` |

### They are not distributed with this source

Upstream states no license for these files: the repository has no license
file, and its README says nothing about one. The working group's other
repositories describe their material as Contributions to the IETF Standards
Process under BCP 78 and BCP 79. With no license to pass on, the public release
of this code does not include them.

Without them, both tests in `tests/rfc9420_vectors.rs` still pass, as skips:
each writes a `SKIPPED` line and these instructions' location to stderr and
returns, so `cargo test` reports them as `ok`. Read the test output (for
example `cargo test --test rfc9420_vectors -- --nocapture`) before taking a
green run as a vector check. To run them, fetch the files into this directory,
from the repository root:

```sh
S=cfd450286d1bfd9cd2519b95c80f9771f94a5b1a
for f in crypto-basics tree-math; do
  curl -sSfL -o "mls/core/tests/vectors/$f.json" \
    "https://raw.githubusercontent.com/mlswg/mls-implementations/$S/test-vectors/$f.json"
done
(cd mls/core/tests/vectors && shasum -a 256 -c) <<'EOF'
17cfcf89af9f51d0f2aa7af77f6f9ec99376a039214b6d42a6f11646b83e8c29  crypto-basics.json
27f04891f56106593b74b674445f01b845e173953770c084deb2f8cf5592e2fc  tree-math.json
EOF
```

The test checks the same hashes itself, so a file from another commit fails
instead of running.

### Why only these two

The rest of the corpus exercises OpenMLS internals that OpenMLS tests itself.
These two cover what this crate depends on directly: `crypto-basics` runs
through `openmls_rust_crypto`, the crypto provider every binding ships (under
suite 0x0001, which shares every 0x004F primitive but the KEM; the X-Wing
vectors below cover the KEM), and `tree-math` checks this crate's own
leaf-index arithmetic.

## X-Wing (draft-06)

`xwing-draft-06.json`: the three vectors of Appendix C of
draft-connolly-cfrg-xwing-kem-06, the X-Wing draft that ciphersuite 0x004F's
KEM follows and that the `x-wing` 0.1.0 crate (the one OpenMLS' provider uses)
implements.

**Source:** the `x-wing` crate, version 0.1.0 on crates.io, file
`tests/test-vectors.json`, copied verbatim.

| File | Bytes | SHA-256 |
|---|---|---|
| `xwing-draft-06.json` | 15,353 | `a8726596f4c7629590f727b1bbeb483f6932292fbf5fd85c9cbb803190014f00` |

Every value in it (`seed`, `eseed`, `ss`, `sk`, `pk`, `ct` for each of the
three) matches Appendix C of the draft byte for byte. The file is the crate's,
under its license: MIT (or Apache-2.0, at your option), Copyright (c)
2024-2026 RustCrypto Developers. It ships with this source.

`tests/xwing_vectors.rs` compiles the file in with `include_str!`, so the test
cannot skip: without the file it does not build. It checks the file's SHA-256,
then for each vector checks deterministic key generation, deterministic
encapsulation and decapsulation, and an HPKE seal and open under 0x004F with
the vector's keys.
