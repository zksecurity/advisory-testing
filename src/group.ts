/**
 * Group parameters: a 2048-bit MODP group with a 256-bit prime-order subgroup
 * (RFC 5114, section 2.3). Signatures live in the order-`q` subgroup generated
 * by `g`.
 */

export const p =
  0x87a8e61db4b6663cffbbd19c651959998ceef608660dd0f25d2ceed4435e3b00e00df8f1d61957d4faf7df4561b2aa3016c3d91134096faa3bf4296d830e9a7c209e0c6497517abd5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c4fdb70c581b23f76b63acae1caa6b7902d52526735488a0ef13c6d9a51bfa4ab3ad8347796524d8ef6a167b5a41825d967e144e5140564251ccacb83e6b486f6b3ca3f7971506026c0b857f689962856ded4010abd0be621c3a3960a54e710c375f26375d7014103a4b54330c198af126116d2276e11715f693877fad7ef09cadb094ae91e1a1597n;

export const q =
  0x8cf83642a709a097b447997640129da299b1a47d1eb3750ba308b0fe64f5fbd3n;

export const g =
  0x3fb32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc41659n;

/** Modular exponentiation, square and multiply. */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/** Modular inverse by the extended Euclidean algorithm. */
export function modInverse(value: bigint, modulus: bigint): bigint {
  let [r0, r1] = [((value % modulus) + modulus) % modulus, modulus];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const quotient = r0 / r1;
    [r0, r1] = [r1, r0 - quotient * r1];
    [s0, s1] = [s1, s0 - quotient * s1];
  }
  if (r0 !== 1n) {
    throw new Error("value is not invertible modulo modulus");
  }
  return ((s0 % modulus) + modulus) % modulus;
}
