# QuantumSafe-SMB-Link Protocol Overview

This repository demonstrates a toy hybrid handshake that combines classical X25519 and post-quantum Kyber-768 to produce shared secrets, derives symmetric keys via HKDF-SHA256, and (optionally) exposes Dilithium signature helpers. Each Rust module focuses on one aspect of the flow; this document describes how they fit together.

## `src/main.rs` — Orchestrating the Handshake

`main` acts as an integration driver:

1. Sets the `hybrid` flag to decide whether to include the classical X25519 leg alongside Kyber.
2. Calls `kem::client_make_hello` to produce a `ClientHello` containing:
   - `x_pub`: the client's X25519 public key (all zeros if `hybrid == false`).
   - `kyber_pub`: serialized Kyber-768 public key bytes.
   - It also keeps the client's optional `EphemeralSecret` plus the Kyber secret key for later.
3. Simulates the server response via `kem::server_reply`, which returns:
   - `ServerHello` with the server's X25519 public key (zeros when not hybrid) and Kyber ciphertext.
   - `Shared` secrets from the server's perspective (optional classical secret + Kyber shared secret bytes).
4. Finalizes the client side with `kem::client_finish`, which decapsulates the Kyber ciphertext and (when hybrid) completes the X25519 ECDH to obtain the same `Shared` structure for the client.
5. Hashes the transcript (`client.x_pub || client.kyber_pub || server.x_pub || server.kyber_ct`) with `Sha256` to produce a pre-authentication salt.
6. Derives transmit/receive keys for each side using `crypto::derive_keys`, passing `is_server = false` for the client and `true` for the server so that their Tx/Rx ordering mirrors each other.
7. Asserts that the derived keys match crosswise (`client_tx == server_rx`, `client_rx == server_tx`) and prints a success message.

This file is also where you'd eventually insert real networking, message serialization, or hook up Dilithium signatures to authenticate hellos.

## `src/kem.rs` — Hybrid KEM / ECDH Layer

This module owns all data-exchange structures and shared-secret construction:

- **Structs**
  - `ClientHello`: X25519 public bytes + Kyber public key bytes.
  - `ServerHello`: server X25519 public bytes + Kyber ciphertext bytes.
  - `Shared`: container holding `Option<[u8; 32]>` for the classical secret and a `Vec<u8>` for the Kyber shared secret.

- **client_make_hello(hybrid)**
  - When `hybrid` is true, generates an `EphemeralSecret` via `OsRng`, derives its 32-byte public key with `XPublic::from`, and returns it alongside the Kyber keypair.
  - When `hybrid` is false, skips X25519 entirely (returns `None` for the secret and a zeroed public key) but still creates a Kyber keypair.

- **server_reply(client_x_pub, client_ky_pk_bytes, hybrid)**
  - If `hybrid`, generates its own X25519 secret and computes the Diffie-Hellman output `ss_x = H(sk_server * pk_client)`.
  - Deserializes the client's Kyber public key, encapsulates with `kyber768::encapsulate`, and collects the shared secret plus ciphertext.
  - Returns a `ServerHello` plus a `Shared` struct containing whichever classical secret exists and the Kyber shared bytes.

- **client_finish(optional_sk, server_x_pub, ky_sk, ct, hybrid)**
  - Validates that an X25519 secret exists when `hybrid` is enabled and computes the matching classical secret, otherwise leaves it `None`.
  - Deserializes the Kyber ciphertext, decapsulates with the stored Kyber secret key, and returns the resulting `Shared`.

Any consumer of this module gets clean, typed access to the transcript components and shared secrets without worrying about serialization details or RNG setup.

## `src/crypto.rs` — Symmetric Primitives

This file holds (optionally used) AEAD helpers plus the key-derivation routine:

- `aead_encrypt` / `aead_decrypt`: thin wrappers around ChaCha20-Poly1305 that enforce a 96-bit nonce, returning `anyhow::Result<Vec<u8>>`. They are marked `#[allow(dead_code)]` because the current demo doesn’t yet encrypt payloads after the handshake.
- `derive_keys(transcript_salt, classical, pq, is_server)`: concatenates the available shared secrets (classical first, followed by Kyber), runs HKDF-SHA256 with the transcript hash as salt, and expands two 32-byte outputs labeled `"QuantumSafe tx"` / `"QuantumSafe rx"`. When `is_server` is true, it swaps the ordering so each side’s TX key equals the other’s RX key, aligning with the assertions in `main`.

If you later add data-plane encryption, these helpers provide the symmetric keys and AEAD ready for use.

## `src/sig.rs` — Dilithium Signatures

Although not currently wired into the handshake, this module provides post-quantum signature utilities:

- `generate_keys`: wraps `dilithium2::keypair`, returning raw public/secret key bytes.
- `sign_detached(msg, sk_bytes)` and `verify_detached(msg, sig_bytes, pk_bytes)`: parse byte slices into Dilithium types, sign messages, and verify detached signatures, all returning `anyhow::Result`.
- A `roundtrip` unit test demonstrates signing `QuantumSafe-SMB-Link` and verifying it.

These helpers can authenticate the exchanged hellos once you introduce a trust model (e.g., server certificates or pre-shared signing keys).

## Putting It All Together

1. **Client**: call `client_make_hello`, send `ClientHello`.
2. **Server**: on receipt, run `server_reply`, send back `ServerHello`, retain `Shared`.
3. **Client**: run `client_finish` with stored secrets and the received `ServerHello`.
4. **Both**: hash transcript → call `derive_keys` (role-dependent) → optionally use `aead_*` for secure channels.
5. **Authentication (future)**: use `sig.rs` helpers or another mechanism to sign and verify the hello messages before trusting the derived keys.

The repository’s `main` binary executes this entire loop locally, making it a convenient reference or starting point for integrating real transport and authentication layers.
