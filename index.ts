import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";

import { asciiToBytes, concatBytes, randomBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2";
import {
  G,
  hasEven,
  toBytes,
  Fn,
  generatePublicKeySignature,
  signPartOne as signFirstRoundForRing,
  generatePublicKeysForRing,
} from "./utils";

//Create a key pair
const signerPrivateKey = secp256k1.utils.randomSecretKey();
const signerPublicKey = secp256k1.getPublicKey(signerPrivateKey);

const NUMBER_OF_RINGS = 2;
// We're going to make every ring the same size for simplicity
const RING_SIZE = 4;
let signerIndex = 2;

if (signerIndex >= RING_SIZE) {
  throw new Error("k is greater than N");
}

const ringIndex = 0;

let ringPubkeyCollection: Uint8Array[][] = Array(NUMBER_OF_RINGS)
  .fill(undefined)
  .map(() =>
    generatePublicKeysForRing(RING_SIZE, signerIndex, signerPublicKey)
  );

let message = asciiToBytes("hello world");

// Create signer nonce
let signerNonce = secp256k1.Point.Fn.fromBytes(randomBytes(32));
let signerNoncePoint = G.multiply(signerNonce);
signerNonce = hasEven(signerNoncePoint.y) ? signerNonce : -signerNonce;

const ringSigCollection: Uint8Array[][] = [];
const lastRingNonceCollection: Uint8Array[] = [];

for (let i = 0; i < NUMBER_OF_RINGS; i++) {
  let pubkeys = ringPubkeyCollection[i];
  let { lastRingNonce, sigs } = signFirstRoundForRing(
    signerNoncePoint,
    message,
    ringIndex,
    signerIndex,
    pubkeys
  );

  ringSigCollection.push(sigs);
  lastRingNonceCollection.push(lastRingNonce);
}

let concatenatedNonces = concatBytes();
for (let i = 0; i < NUMBER_OF_RINGS; i++) {
  let lastRingNonce = lastRingNonceCollection[i];
  concatenatedNonces = concatBytes(concatenatedNonces, lastRingNonce);
}

let sharedRootMessageHash = Fn.fromBytes(sha256(concatenatedNonces));

for (let j = 0; j < NUMBER_OF_RINGS; j++) {
  let e_i = sharedRootMessageHash;
  // Fill in signatures from 0 to signer's index
  for (let i = 0; i < signerIndex; i++) {
    let pubkeys = ringPubkeyCollection[j];
    let { signature, noncePoint } = generatePublicKeySignature(
      pubkeys[i].slice(1),
      e_i
    );

    ringSigCollection[j][i] = signature;
    e_i = Fn.fromBytes(
      sha256(
        concatBytes(
          message,
          toBytes(noncePoint.X),
          new Uint8Array([ringIndex]),
          toBytes(BigInt(signerIndex))
        )
      )
    );
  }

  let sig = new Uint8Array(64);
  sig.set(toBytes(signerNoncePoint.x), 0);
  let s = signerNonce + e_i * Fn.fromBytes(signerPrivateKey);
  s = Fn.create(s);
  sig.set(toBytes(s), 32);
  ringSigCollection[j][signerIndex] = sig;
}

console.log(ringSigCollection);
