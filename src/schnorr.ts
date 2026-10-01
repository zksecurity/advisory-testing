import { createHash, randomBytes } from "node:crypto";
import { g, modInverse, modPow, p, q } from "./group";

export type KeyPair = { privateKey: bigint; publicKey: bigint };
export type Signature = { R: bigint; s: bigint };

const bytesToBigInt = (bytes: Buffer): bigint =>
  BigInt(`0x${bytes.toString("hex")}`);

/** SHA-512 of the parts, reduced into the scalar field. */
function hashToScalar(...parts: string[]): bigint {
  const digest = createHash("sha512");
  for (const part of parts) {
    digest.update(Buffer.from(part, "utf8"));
    digest.update(Buffer.from([0x1f]));
  }
  return bytesToBigInt(digest.digest()) % q;
}

export function generateKeyPair(): KeyPair {
  // Rejection sampling keeps the key uniform over [1, q).
  for (;;) {
    const candidate = bytesToBigInt(randomBytes(32));
    if (candidate > 0n && candidate < q) {
      return { privateKey: candidate, publicKey: modPow(g, candidate, p) };
    }
  }
}

/**
 * Per-signature nonce.
 *
 * Derived from the message rather than drawn from the RNG, so signing is
 * deterministic: the same message always yields the same signature, which keeps
 * signatures reproducible across platforms and removes any dependence on the
 * quality of the host RNG at signing time.
 */
function deriveNonce(message: string): bigint {
  const k = hashToScalar("schnorr-lite/nonce", message);
  // A zero nonce would leak the key outright, so step past it.
  return k === 0n ? 1n : k;
}

/** The Fiat-Shamir challenge, binding the commitment, the key and the message. */
function challenge(R: bigint, publicKey: bigint, message: string): bigint {
  return hashToScalar(
    "schnorr-lite/challenge",
    R.toString(16),
    publicKey.toString(16),
    message
  );
}

export function sign(message: string, privateKey: bigint): Signature {
  const k = deriveNonce(message);
  const R = modPow(g, k, p);
  const publicKey = modPow(g, privateKey, p);
  const c = challenge(R, publicKey, message);
  const s = (k + c * privateKey) % q;
  return { R, s };
}

export function verify(
  message: string,
  signature: Signature,
  publicKey: bigint
): boolean {
  const { R, s } = signature;
  if (R <= 0n || R >= p || s < 0n || s >= q) {
    return false;
  }
  if (modPow(R, q, p) !== 1n) {
    return false;
  }
  const c = challenge(R, publicKey, message);
  const left = modPow(g, s, p);
  const right = (R * modPow(publicKey, c, p)) % p;
  return left === right;
}

export { challenge, deriveNonce, modInverse };
