import { secp256k1 } from "@noble/curves/secp256k1.js";

import { asciiToBytes, concatBytes, randomBytes } from "@noble/curves/utils.js";
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
} from "./utils";
import { invert } from "@noble/curves/abstract/modular";

//Create a key pair
let signerPrivateKey = secp256k1.utils.randomSecretKey();
let signerPublicKey = secp256k1.getPublicKey(signerPrivateKey);

//21
let value = new Uint8Array([0x15]);
// this needs to be checked for sqrt and this might not work
let H = lift_x(Fn.fromBytes(secp256k1.utils.randomSecretKey()));
let C = H.multiply(Fn.fromBytes(value)).add(G.multiply(Fn.fromBytes(signerPrivateKey)))

//
// publickKeysForRound.push(R)
// publickKeysForRound.push(C - 2*j)



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

//Prove, step (2)
for (let ringIndex = 0; ringIndex < NUMBER_OF_RINGS; ringIndex++) {

  // for(let i = 0; i < signerIndex; i++) {
  //   let r = secp256k1.utils.randomSecretKey();
  //   lastRingNonceCollection.push(r);
  // }

  let pubkeys = ringPubkeyCollection[ringIndex];
  let { lastRingNonce, sigs, lastMessageHash } = signFirstRoundForRing(
    signerNoncePoint,
    message,
    ringIndex,
    signerIndex,
    pubkeys
  );

  ringSigCollection.push(sigs);

  let ringValue = 1 << ringIndex;
  let R_i;

  if(Fp.fromBytes(value) & BigInt(ringValue)) {
    // C_i = r*G + v*H
    let v = BigInt(1 << ringValue);
    let vH = H.multiply(v);
    let C_i = G.multiply(Fn.fromBytes(signerPrivateKey)).add(vH)
    R_i = C_i.multiply(lastMessageHash)
  }
  else {
    let r = secp256k1.utils.randomSecretKey();
    R_i = G.multiply(Fn.fromBytes(r));
  }


  lastRingNonceCollection.push(toBytes(R_i.x));
}


// (3)
let concatenatedNonces = concatBytes();
for (let i = 0; i < NUMBER_OF_RINGS; i++) {
  let lastRingNonce = lastRingNonceCollection[i];
  concatenatedNonces = concatBytes(concatenatedNonces, lastRingNonce);
}

let sharedRootMessageHash = Fn.fromBytes(sha256(concatenatedNonces));


// (4)
for (let ringIndex = 0; ringIndex < NUMBER_OF_RINGS; ringIndex++) {
  let e_i = sharedRootMessageHash;
  // Fill in signatures from 0 to signer's index

  let ringValue = 1 << ringIndex;
  for (let pubkeyIndex = 0; pubkeyIndex < signerIndex; pubkeyIndex++) {
    let pubkeys = ringPubkeyCollection[ringIndex];

    //change this
    let { signature, noncePoint } = generatePublicKeySignature(
      pubkeys[pubkeyIndex].slice(1),
      e_i
    );

    
    let R_i;

    if(Fp.fromBytes(value) & BigInt(ringValue)) {
      // // C_i = r*G + v*H
      // let v = BigInt(1 << ringValue);
      // let vH = H.multiply(v);
      // let C_i = G.multiply(Fn.fromBytes(signerPrivateKey)).add(vH)
      // R_i= C_i.multiply(lastMessageHash)



    }
    else {

      // I put coefficients in 'lastRingNonceCollection' but I should break them into their own arr
      // C_i = (k[i]/e_i)*G 
      // (k[i]/e_i) is our blinding factor and there's no value component because the value
      // contribution of this ring is 0

      let k = Fn.fromBytes(lastRingNonceCollection[ringIndex]);
      let e_i_inverse = invert(k, Fn.ORDER)
      let blindCoeff = k * e_i_inverse;
      // let C_i = G.multiply(blindCoeff);


      // k
      let r = Fn.fromBytes(secp256k1.utils.randomSecretKey());
      // m[i]*j
      let v = BigInt(1 << ringValue);

      // k + e*(m[i]*j)*H
      //The above is what happens when you set v in 'sG - e*(rG + 0*H - m[i]*j*H)'
      let preimage = r + H.multiply(v).multiply(e_i).x
      R_i = G.multiply(r);
      signature = toBytes(r + e_i*blindCoeff)

       e_i = Fn.fromBytes(
        sha256(
          toBytes(preimage)
        )
      );
    }

    ringSigCollection[ringIndex][pubkeyIndex] = signature;
  }

  let sig = new Uint8Array(32);
  // sig.set(toBytes(signerNoncePoint.x), 0);
  let s = signerNonce - e_i * Fn.fromBytes(signerPrivateKey);
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
    noncePoint = sG.add(eP);

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
