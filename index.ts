import { secp256k1 } from "@noble/curves/secp256k1.js";

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
  lift_x,
} from "./utils";

//Create a key pair
let signerPrivateKey = secp256k1.utils.randomSecretKey();
let signerPublicKey = secp256k1.getPublicKey(signerPrivateKey);

// Normalize signer key to even-Y for x-only/BIP340 math
const signerPoint = secp256k1.Point.fromHex(signerPublicKey);
if (!hasEven(signerPoint.y)) {
  const d = Fn.fromBytes(signerPrivateKey);
  const dNeg = Fn.create(-d);
  signerPrivateKey = Fn.toBytes(dNeg);
  signerPublicKey = secp256k1.getPublicKey(signerPrivateKey);
}

const NUMBER_OF_RINGS = 2;
// We're going to make every ring the same size for simplicity
const RING_SIZE = 4;
let signerIndex = 2;

if (signerIndex >= RING_SIZE) {
  throw new Error("k is greater than N");
}

let ringPubkeyCollection: Uint8Array[][] = Array(NUMBER_OF_RINGS)
  .fill(undefined)
  .map(() =>
    generatePublicKeysForRing(RING_SIZE, signerIndex, signerPublicKey)
  );

let message = asciiToBytes("hello world");

// Create signer nonce
let signerNonce = secp256k1.Point.Fn.fromBytes(randomBytes(32));
let signerNoncePoint = G.multiply(signerNonce);
signerNonce = Fn.create(
  hasEven(signerNoncePoint.y) ? signerNonce : -signerNonce
);
signerNoncePoint = G.multiply(signerNonce);

const ringSigCollection: Uint8Array[][] = [];
const lastRingNonceCollection: Uint8Array[] = [];

for (let ringIndex = 0; ringIndex < NUMBER_OF_RINGS; ringIndex++) {
  let pubkeys = ringPubkeyCollection[ringIndex];
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

for (let ringIndex = 0; ringIndex < NUMBER_OF_RINGS; ringIndex++) {
  let e_i = sharedRootMessageHash;
  // Fill in signatures from 0 to signer's index
  for (let pubkeyIndex = 0; pubkeyIndex < signerIndex; pubkeyIndex++) {
    let pubkeys = ringPubkeyCollection[ringIndex];
    let { signature, noncePoint } = generatePublicKeySignature(
      pubkeys[pubkeyIndex].slice(1),
      e_i
    );

    ringSigCollection[ringIndex][pubkeyIndex] = signature;
    e_i = Fn.fromBytes(
      sha256(
        concatBytes(
          message,
          toBytes(noncePoint.x),
          new Uint8Array([ringIndex]),
          toBytes(BigInt(pubkeyIndex))
        )
      )
    );
  }

  let sig = new Uint8Array(32);
  // sig.set(toBytes(signerNoncePoint.x), 0);
  let s = signerNonce + e_i * Fn.fromBytes(signerPrivateKey);
  s = Fn.create(s);
  sig.set(toBytes(s), 0);
  ringSigCollection[ringIndex][signerIndex] = sig;
}

//VERIFY
//For each ring
for (let ringIndex = 0; ringIndex < NUMBER_OF_RINGS; ringIndex++) {
  let signatures = ringSigCollection[ringIndex];
  let pubkeys = ringPubkeyCollection[ringIndex];
  let e_i = sharedRootMessageHash;
  let noncePoint;
  for (let pubkeyIndex = 0; pubkeyIndex < signatures.length; pubkeyIndex++) {
    let xOnlyPubkey = pubkeys[pubkeyIndex].slice(1);
    let signature = Fn.fromBytes(signatures[pubkeyIndex]);
    let sG = G.multiply(signature);
    const P = lift_x(Fn.fromBytes(xOnlyPubkey));
    let eP = P.multiply(e_i);
    noncePoint = sG.add(eP.negate());

    let messagePreimage = concatBytes(
      message,
      toBytes(noncePoint.x),
      new Uint8Array([ringIndex]),
      toBytes(BigInt(pubkeyIndex))
    );

    e_i = Fn.fromBytes(sha256(messagePreimage));
  }

  if (noncePoint.x !== Fn.fromBytes(lastRingNonceCollection[ringIndex])) {
    throw new Error(`Failed on ring ${ringIndex + 1}/${NUMBER_OF_RINGS}`);
  }
}
console.log("Validation successful");
