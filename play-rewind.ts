import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, randomBytes, toBytes } from "@noble/hashes/utils";
import crypto from "crypto";

// Reset change
import getMessage from "./message";
import { secp256k1_borromean_sign2 } from ".";
import { CurvePoint } from "@noble/curves/abstract/curve";

function secp256k1_rfc6979_hmac_sha256_initialize(key: any) {
  const rng = {
    v: Buffer.alloc(32, 0x01), // Initialize with 0x01 bytes
    k: Buffer.alloc(32, 0x00), // Initialize with 0x00 bytes
    retry: 0,
  };

  // Helper function for HMAC operations
  function hmacSha256(k: any, ...data: any) {
    const hmac = crypto.createHmac("sha256", k);
    data.forEach((chunk: any) => hmac.update(chunk));
    return hmac.digest();
  }

  const zero = Buffer.from([0x00]);
  const one = Buffer.from([0x01]);

  // RFC6979 3.2.d.
  rng.k = hmacSha256(rng.k, rng.v, zero, key);
  rng.v = hmacSha256(rng.k, rng.v);

  // RFC6979 3.2.f.
  rng.k = hmacSha256(rng.k, rng.v, one, key);
  rng.v = hmacSha256(rng.k, rng.v);

  return rng;
}

function secp256k1_rfc6979_hmac_sha256_generate(rng: any, outlen: any) {
  /* RFC6979 3.2.h. */
  const zero: any = Buffer.from([0x00]);

  if (rng.retry) {
    // K = HMAC_K(V || 0x00)
    let hmac = crypto.createHmac("sha256", rng.k);
    hmac.update(rng.v);
    hmac.update(zero);
    rng.k = hmac.digest();

    // V = HMAC_K(V)
    hmac = crypto.createHmac("sha256", rng.k);
    hmac.update(rng.v);
    rng.v = hmac.digest();
  }

  const out = Buffer.alloc(outlen);
  let outOffset = 0;
  let remainingLen = outlen;

  while (remainingLen > 0) {
    // V = HMAC_K(V)
    const hmac = crypto.createHmac("sha256", rng.k);
    hmac.update(rng.v);
    rng.v = hmac.digest();

    const now = Math.min(remainingLen, 32);
    rng.v.copy(out, outOffset, 0, now);
    outOffset += now;
    remainingLen -= now;
  }

  rng.retry = 1;
  return out;
}

export const toBytesFn = secp256k1.Point.Fn.toBytes;
export const hasEven = (y: bigint) => y % BigInt(2) === BigInt(0);
export const Fn = secp256k1.Point.Fn;
export const Fp = secp256k1.Point.Fp;
export const { lift_x } = schnorr.utils;
export const G = secp256k1.Point.BASE;
export const num = bytesToNumberBE;
let Point = secp256k1.Point;

const NUM_RINGS = 26;
const LAST_RING_INDEX = NUM_RINGS - 1;
const STANDRAD_RING_SIZE = 4;

export function genrand(
  nonce: bigint,
  commitVal: Uint8Array,
  serializedGenPS: Uint8Array,
  message: Uint8Array
) {
  let tmp;
  let decryptionKeys: any[] = [];

  let hmacKey = Buffer.concat([
    toBytesFn(nonce),
    commitVal,
    serializedGenPS,
    new Uint8Array(proofHeader),
  ]);

  const rng = secp256k1_rfc6979_hmac_sha256_initialize(hmacKey);
  let acc = 0n;

  for (let i = 0; i < NUM_RINGS; i++) {
    if (i != LAST_RING_INDEX) {
      //secp256k1_rfc6979_hmac_sha256_generate mutates rng
      secp256k1_rfc6979_hmac_sha256_generate(rng, 32);
      tmp = secp256k1_rfc6979_hmac_sha256_generate(rng, 32);
      // Force into Fp
      // console.log(Buffer.from(toBytes(Fp.fromBytes(sec[0]))).toString("hex"));
      acc += BigInt("0x" + tmp.toString("hex"));
      // TODO: Add checks for overflow and 0 and retry when they occur
    }

    if (tmp === undefined) {
      throw new Error("tmp should not be undefined");
    }

    for (let j = 0; j < STANDRAD_RING_SIZE; j++) {
      tmp = secp256k1_rfc6979_hmac_sha256_generate(rng, 32);

      if (message) {
        const ENCRYPTION_CHUNK_SIZE = 32;
        for (let b = 0; b < ENCRYPTION_CHUNK_SIZE; b++) {
          tmp[b] ^=
            message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b];
          message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b] =
            tmp[b];
        }
      }

      decryptionKeys.push(tmp);
    }
  }

  return decryptionKeys;
}

export function getQuadness(pubkey: CurvePoint<any, any>) {
  try {
    Fp.sqrt(pubkey.y);
    return 0;
  } catch (e) {
    return 1;
  }
}

let proofHeader = new Array(10).fill(0).reduce((acc: Buffer, n) => {
  return Buffer.from([...acc, n]);
}, Buffer.from([]));

proofHeader[0] = 0x60;
proofHeader[1] = 0x33;
proofHeader[9] = 0x01;

export function generateRangeProof2(
  serializedPoint: Uint8Array,
  serializedGenP: Uint8Array,
  nonce: bigint,
  valueB: bigint,
  extraCommit: Uint8Array,
  assetId: string,
  assetBlind: string,
  sharedRootMessageHash: Uint8Array,
  genP: CurvePoint<any, any>
) {
  let pubs: CurvePoint<any, any>[][] = [];

  let hmacKey = Buffer.concat([
    toBytesFn(nonce),
    serializedPoint,
    serializedGenP,
    new Uint8Array(proofHeader),
  ]);

  const rng = secp256k1_rfc6979_hmac_sha256_initialize(hmacKey);

  let sec: any[] = [];

  let secidx: any[] = [];

  for (let i = 0; i < NUM_RINGS; i++) {
    secidx[i] = Number(valueB >> BigInt(i * 2)) & 3;
  }

  let valueHex = Buffer.from(numberToBytesBE(valueB, 8)).toString("hex");
  let message = getMessage(
    NUM_RINGS,
    STANDRAD_RING_SIZE,
    assetId,
    assetBlind,
    valueHex,
    secidx[LAST_RING_INDEX] === STANDRAD_RING_SIZE - 1
  );

  let messageCopy = message.slice();

  let acc = 0n;

  let sigs: Uint8Array[][] = [];

  let tmp;
  for (let i = 0; i < NUM_RINGS; i++) {
    sigs.push([]);
    if (i != LAST_RING_INDEX) {
      //secp256k1_rfc6979_hmac_sha256_generate mutates rng
      secp256k1_rfc6979_hmac_sha256_generate(rng, 32);
      tmp = secp256k1_rfc6979_hmac_sha256_generate(rng, 32);
      sec.push(tmp);
      // Force into Fp
      // console.log(Buffer.from(toBytes(Fp.fromBytes(sec[0]))).toString("hex"));
      acc += BigInt("0x" + tmp.toString("hex"));
      // TODO: Add checks for overflow and 0 and retry when they occur
    } else {
      let negativeSum = Fn.create(0n - acc);
      sec.push(Buffer.from(negativeSum.toString(16), "hex"));
    }

    if (tmp === undefined) {
      throw new Error("tmp should not be undefined");
    }

    for (let j = 0; j < STANDRAD_RING_SIZE; j++) {
      tmp = secp256k1_rfc6979_hmac_sha256_generate(rng, 32);

      if (message) {
        const ENCRYPTION_CHUNK_SIZE = 32;
        for (let b = 0; b < ENCRYPTION_CHUNK_SIZE; b++) {
          tmp[b] ^=
            message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b];
          message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b] =
            tmp[b];
        }
      }

      sigs[i].push(tmp);
    }
  }

  let k: Uint8Array[] = [];

  let signsBufferSize = Math.ceil(NUM_RINGS / 8);
  let signs = new Uint8Array(Array(signsBufferSize).fill(0));

  for (let i = 0; i < NUM_RINGS; i++) {
    k.push(sigs[i][secidx[i]]);
    sigs[i][secidx[i]] = Buffer.from(Array(32).fill(0)) as Uint8Array;
  }

  // let sumOfBlindAndLastPartialBlind = Fn.fromBytes(sec[sec.length - 1]) + ephemeralOutputBlind;
  // sec[sec.length - 1] = Buffer.from(Fn.toBytes(Fn.create(sumOfBlindAndLastPartialBlind)));

  //RANDY_NEW
  for (let i = 0; i < NUM_RINGS; i++) {
    // secp256k1_pedersen_ecmult(ecmult_gen_ctx, &pubs[npub], &sec[i], ((uint64_t)secidx[i] * scale) << (i*2), genp);
    //TODO: This is buggy. Fix it: 'Field.fromBytes: expected 32 bytes, got 31'
    let bG = G.multiply(Fn.fromBytes(sec[i]));
    // let bG2 = lift_x(Fn.fromBytes(sec[i])); // Makes a new point L

    let vValue = BigInt(BigInt(secidx[i]) << (BigInt(i) * 2n));

    let C: CurvePoint<any, any> | undefined;

    if (vValue === 0n) {
      C = bG;
    } else {
      let vP = genP.multiply(Fn.create(vValue));
      C = bG.add(vP);
    }

    pubs[i] = [C!];

    let byteIndex = Math.floor(i / 8);
    let bitPosition = i % 8;
    if (i < NUM_RINGS - 1) {
      signs[byteIndex] |= getQuadness(C!) << bitPosition;
    }
  }

  let negativeGenP = genP.negate();
  //secp256k1_rangeproof_pub_expand
  for (let i = 0; i < NUM_RINGS; i++) {
    for (let j = 1; j < STANDRAD_RING_SIZE; j++) {
      pubs[i].push((pubs[i][j - 1] as any).add(negativeGenP));
    }
    negativeGenP = negativeGenP.multiply(4n);
  }

  console.log();

  //TODO: Look at that special logic using '-=' when setting prep

  // Revisit why last sig was wrong
  // was 62bd36f29749b407e2531c0e54de2ee3486b1cae01c6166ca45c845e810d17d9, expected e2bd36f29749b407e2531c0e54de2ee3486b1cae01c6166ca45c845e810d17d9
  //TODO: Figure out what's wrong here
  //Reset (doesnt need reset but I'm putting it here to draw attention)
  // sigs[NUM_RINGS - 1][3] = Buffer.from(0xe2bd36f29749b407e2531c0e54de2ee3486b1cae01c6166ca45c845e810d17d9n.toString(16), "hex") as Uint8Array;

  let ringPubkeysForMessage = pubs.map((ringPubkeys) => {
    let serializedRingPubkey = ringPubkeys[0].toBytes();

    try {
      Fp.sqrt(ringPubkeys[0].y);
      serializedRingPubkey[0] = 0;
    } catch (e) {
      serializedRingPubkey[0] = 1;
    }

    return serializedRingPubkey;
  });

  ringPubkeysForMessage.pop();

  let messagePreimage = concatBytes(
    serializedPoint,
    serializedGenP,
    proofHeader as Uint8Array,
    ...ringPubkeysForMessage,
    extraCommit
  );

  let messageHashForSignature = sha256(messagePreimage);

  //last pub
  // x f05833effa5f745e5999d84494fd6812474fc0872f00a0765b9149d6448f92d105335b77fdfe5
  // y 9374c7456160001b94d77e5ce908000434cc1ef90fb7000a512852dd189200105335b77fdfe5

  let {sharedRootMessageHash: e0, es} = secp256k1_borromean_sign2(
    sigs,
    pubs,
    k,
    sec,
    secidx,
    NUM_RINGS,
    messageHashForSignature,
    sharedRootMessageHash
  );

  console.log();

  let commitmentBuffer = ringPubkeysForMessage.reduce((acc, val) => {
    return concatBytes(acc, val.subarray(1));
  }, new Uint8Array());

  let sigBuffer = sigs.reduce((acc: any, sigArray: any) => {
    let serializedSigArray = sigArray.reduce((acc2: any, val2: any) => {
      return concatBytes(acc2, val2);
    }, new Uint8Array());
    return concatBytes(acc, serializedSigArray);
  }, new Uint8Array());

  let finalProof = concatBytes(
    proofHeader as Uint8Array, // 10
    signs, // 4
    commitmentBuffer, // 800
    Fn.toBytes(e0!), //32
    //846
    sigBuffer // 3328
  );

  return {finalProof, k, es, sec};
}
