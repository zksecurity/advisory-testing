# schnorr-lite

Schnorr signatures over a 2048-bit MODP group with a 256-bit prime-order
subgroup (RFC 5114, §2.3). Pure TypeScript, `BigInt` arithmetic, no native
dependencies.

> This repository exists to exercise zkao's security advisory and report intake
> flows. The code is synthetic and is not used anywhere.

## Usage

```ts
import { generateKeyPair, sign, verify } from "./src/index";

const keys = generateKeyPair();
const sig = sign("transfer 100 to alice", keys.privateKey);
verify("transfer 100 to alice", sig, keys.publicKey); // true
```

## Design notes

Nonces are derived deterministically from the message, so signing needs no
entropy source at call time and the same message always produces the same
signature. That makes signatures reproducible across platforms and removes any
dependency on the quality of the host RNG during signing.

## Running the tests

```sh
bun test
```
