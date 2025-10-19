import { secp256k1 } from "@noble/curves/secp256k1.js";

import {
  asciiToBytes,
  concatBytes,
  numberToBytesBE,
  randomBytes,
} from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2";
import {
  G,
  hasEven,
  toBytes,
  Fn,
  Fp,
  generatePublicKeySignature,
  signPartOne as signFirstRoundForRing,
  generatePublicKeysForRing,
  lift_x,
  invert2
} from "./utils";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { CurvePoint } from "@noble/curves/abstract/curve";

// let ringPubkeyCollection: Uint8Array[][] = Array(NUMBER_OF_RINGS)
//   .fill(undefined)
//   .map(() =>
//     generatePublicKeysForRing(RING_SIZE, signerIndex, signerPublicKey)
//   );

function getArrayWithRandomByteValues(size: number): Uint8Array[] {
  return Array(size)
    .fill(undefined)
    .map((_) => randomBytes(32));
}

const NUMBER_OF_RINGS = 2;

let rsizes = Array(26).fill(4);

let s = Array(NUMBER_OF_RINGS)
  .fill(undefined)
  .map((_, index) => getArrayWithRandomByteValues(rsizes[index]));

let sec = Array(NUMBER_OF_RINGS)
  .fill(undefined)
  .map((_) => randomBytes(32));

// For range proof, secidx is determined by secidx[i] = (*v >> (i*2)) & 3;
let secidx = Array(NUMBER_OF_RINGS)
  .fill(undefined)
  .map((_, index) => {
    let randomBytesForSecretIndex = randomBytes(32);
    const dataView = new DataView(randomBytesForSecretIndex.buffer);
    return dataView.getUint32(0, false) % rsizes[index];
  });

let pubs: Uint8Array[][] = Array(NUMBER_OF_RINGS)
  .fill(undefined)
  .map((_val, index) =>
    generatePublicKeysForRing(
      rsizes[index],
      secidx[index],
      secp256k1.getPublicKey(sec[index])
    )
  );

let k = Array(NUMBER_OF_RINGS)
  .fill(undefined)
  .map((_) => randomBytes(32));

//secp256k1_borromean_sign([], ringPubkeyCollection,
//Return e0e0,

// secp256k1_borromean_sign(s, pubs, k, sec, secidx, NUMBER_OF_RINGS, message);

export function secp256k1_borromean_sign(
  s: Uint8Array[][],
  pubs: CurvePoint<any, any>[][],
  k: Uint8Array[],
  sec: Uint8Array[],
  secidx: number[],
  nrings: number,
  m: any,
  skipSig: boolean = false
) {
  let es: any[] = [];
  const lastRingNonceCollection: Uint8Array[] = [];

  for (let ringIndex = 0; ringIndex < nrings; ringIndex++) {
    let signerNoncePoint = G.multiply(Fp.fromBytes(k[ringIndex]));

    //  if(ringIndex === 25) {
    //   debugger;
    //  }

    let pubkeys = pubs[ringIndex];
    let { lastRingNonce } = signFirstRoundForRing(
      signerNoncePoint.toBytes(),
      m,
      ringIndex,
      secidx[ringIndex],
      pubkeys,
      s
    );

    lastRingNonceCollection.push(lastRingNonce);
  }

  let concatenatedNonces = concatBytes();
  for (let i = 0; i < nrings; i++) {
    let lastRingNonce = lastRingNonceCollection[i];
    concatenatedNonces = concatBytes(concatenatedNonces, lastRingNonce);
  }

  concatenatedNonces = concatBytes(concatenatedNonces, m);

  let xx = sha256(concatenatedNonces);
  let sharedRootMessageHash = Fn.fromBytes(sha256(concatenatedNonces));
  //correct hash should be: 1a4a550fee295a980018512f7fa9129db8e7bddd4eece99b7c2be41617bea1fa

  for (let ringIndex = 0; ringIndex < nrings; ringIndex++) {
    let signerIndex = secidx[ringIndex];

    let e_i = Fn.fromBytes(
      sha256(
        concatBytes(
          toBytes(sharedRootMessageHash),
          m,
          numberToBytesBE(ringIndex, 4),
          numberToBytesBE(0, 4)
        )
      )
    );

    // Fill in signatures from 0 to signer's index
    for (let pubkeyIndex = 0; pubkeyIndex < signerIndex; pubkeyIndex++) {
      let pubkeys = pubs[ringIndex];
      let { noncePoint } = generatePublicKeySignature(
        pubkeys[pubkeyIndex],
        e_i,
        s[ringIndex][pubkeyIndex]
      );

      // The message hash preimage format differs from the paper here,
      // and instead follows the secp256k1-zkp library implementation
      e_i = Fn.fromBytes(
        sha256(
          concatBytes(
            noncePoint.toBytes(),
            m,
            numberToBytesBE(ringIndex, 4),
            numberToBytesBE(pubkeyIndex + 1, 4)
          )
        )
      );
    }

    es.push(e_i);

    /* sig/sec[ringIndex]
    s = k - e*sec
   (s - k)/-e = sec
   (k - s)/e = sec
    */

    // Overwrite fake signature in the signer index with a real signature from the signer
    // Fn for private key

    // if (ringIndex === 25 || ringIndex === 1) {
    //     debugger;
    //   }
    if (!skipSig) {

      let signerSignature =
        Fp.fromBytes(k[ringIndex]) -
        Fp.create(e_i) * Fn.fromBytes(sec[ringIndex]);
      s[ringIndex][signerIndex] = toBytes(Fn.create(signerSignature));
    }
  }

  return { sharedRootMessageHash, es };
}

export function secp256k1_borromean_sign2(
  s: Uint8Array[][],
  pubs: CurvePoint<any, any>[][],
  k: Uint8Array[],
  sec: Uint8Array[],
  secidx: number[],
  nrings: number,
  m: any,
  sharedRootMessageHash: Uint8Array
) {
  let es: any[] = [];

  for (let ringIndex = 0; ringIndex < nrings; ringIndex++) {
    let signerIndex = secidx[ringIndex];

    let e_i = Fn.fromBytes(
      sha256(
        concatBytes(
          sharedRootMessageHash,
          m,
          numberToBytesBE(ringIndex, 4),
          numberToBytesBE(0, 4)
        )
      )
    );

    // Fill in signatures from 0 to signer's index
    for (let pubkeyIndex = 0; pubkeyIndex < signerIndex; pubkeyIndex++) {
      let pubkeys = pubs[ringIndex];
      let { noncePoint } = generatePublicKeySignature(
        pubkeys[pubkeyIndex],
        e_i,
        s[ringIndex][pubkeyIndex]
      );

      // The message hash preimage format differs from the paper here,
      // and instead follows the secp256k1-zkp library implementation
      e_i = Fn.fromBytes(
        sha256(
          concatBytes(
            noncePoint.toBytes(),
            m,
            numberToBytesBE(ringIndex, 4),
            numberToBytesBE(pubkeyIndex + 1, 4)
          )
        )
      );
    }

    es.push(e_i);

    /* sig/sec[ringIndex]
    s = k - e*sec
   (s - k)/-e = sec
   (k - s)/e = sec
    */

    // Overwrite fake signature in the signer index with a real signature from the signer
    // Fn for private key

    // if (ringIndex === 25 || ringIndex === 1) {
    //     debugger;
    //   }
  }

  return { sharedRootMessageHash: Fn.fromBytes(sharedRootMessageHash), es };
}
console.log();
