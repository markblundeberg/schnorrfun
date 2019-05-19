# schnorrfun

1. Everyone runs setup.py to make key shares.
2. Everyone runs sign.py to sign a transaction.
3. No thresholds on this one, just N-of-N.
4. Awkward

## How it works:

Setup:

- Parties generate random private keys.
- Parties exchange pubkey commitments (hashes).
- After all hashes are exchanged, pubkeys are revealed.
- Aggregate pubkey is just the sum of these keys.

Random key and commitment phase is important to avoid key cancellation attacks. Could do MuSig instead but meh, it's just setup so who cares.

Signing:

- Parties agree on a message to sign.
- Parties generate random nonce k_i and R_i.
- Parties exchange R_i commitments (hashes), signed with their individual key.
- After all hashes are exchanged, R_i points are revealed.
- Aggregate R is sum of R_i points.
- If R's y coordinate has jacobi symbol -1, then all parties negate k and R_i for the following process.
- Let rbytes = R.x() encoded as 32-byte big endian.
- Let e = SHA256(rbytes + aggpub + message) decoded as big endian integer.
- Parties calculate s = k + e*privatekey and share s values
- Parties verify each other's s values according to s_i*G == R_i + e*pub_i.
- Parties assemble final sig by summing s values.

The R commitment phase likewise avoids rogue point attacks. Non-deterministic randomness of k is crucial to avoid retry attacks (see MuSig paper).

## How to get tx for signing

To get a transaction for signing is really annoying right now.

- Start Electron Cash.
- Make watching-only wallet for the aggregate address.
- Make unsigned transaction and save hex.
- Manually edit the hex:
  - strip out the extra value field after sequence.
  - strip out the scriptsig.
- Share with peers.
- Peers can inspect the tx using Electron Cash | Load Transaction.
