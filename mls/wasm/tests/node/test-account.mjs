// SPDX-License-Identifier: MIT
// The account keys behind `TestIssuer` credentials, for the node tests.
//
// `TestIssuer.issue(actor, …)` certifies the device under a stand-in account
// key per actor (`test_account_key` in mls/core/src/issuer.rs). A client must
// be opened naming the identity key it holds,
// `accountIdentityPublicKey(testAccountKey(actor))`, or a certified credential
// is refused as `not_own_account_key`.

import { createHash } from 'node:crypto';

/** `SHA-256("peachy-test-account" || 0x00 || utf8(actor))`. */
export function testAccountKey(actor) {
  return new Uint8Array(
    createHash('sha256')
      .update('peachy-test-account')
      .update(new Uint8Array([0]))
      .update(actor, 'utf8')
      .digest(),
  );
}
