import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, randomBytes, toBytes } from "@noble/hashes/utils";
import crypto from "crypto";

// Reset change
import getMessage from "./message";
import { secp256k1_scalar_add } from "./scalar_add";
import { secp256k1_borromean_sign } from ".";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
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

let arrToPoint = (arr: Array<bigint>): bigint => {
  return arr.reduce((acc: bigint, curr, i: number): bigint => {
    return acc + (BigInt(curr) << (BigInt(i) * BigInt(52)));
  }, 0n);
};

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

export function generateRangeProof(
  serializedPoint: Uint8Array,
  serializedGenP: Uint8Array,
  ephemeralOutputBlind: bigint,
  nonce: bigint,
  valueB: bigint,
  extraCommit: Uint8Array,
  assetId: string,
  assetBlind: string
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

  let k: any[] = [];

  let signsBufferSize = Math.ceil(NUM_RINGS / 8);
  let signs = new Uint8Array(Array(signsBufferSize).fill(0));

  for (let i = 0; i < NUM_RINGS; i++) {
    k.push(sigs[i][secidx[i]]);
    sigs[i][secidx[i]] = Buffer.from(Array(32).fill(0)) as Uint8Array;
  }

  let sumOfBlindAndLastPartialBlind = Fn.fromBytes(sec[sec.length - 1]) + ephemeralOutputBlind;
  sec[sec.length - 1] = Buffer.from(Fn.toBytes(Fn.create(sumOfBlindAndLastPartialBlind)));

  //RANDY_NEW
  for (let i = 0; i < NUM_RINGS; i++) {
    // secp256k1_pedersen_ecmult(ecmult_gen_ctx, &pubs[npub], &sec[i], ((uint64_t)secidx[i] * scale) << (i*2), genp);
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

  console.log("sec: " + Buffer.from(sec[LAST_RING_INDEX]).toString("hex"));
  let {sharedRootMessageHash: e0} = secp256k1_borromean_sign(
    sigs,
    pubs,
    k,
    sec,
    secidx,
    NUM_RINGS,
    messageHashForSignature,
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
  // console.log("\n\nProof:\n\n", Buffer.from(finalProof).toString("hex"));

  return {finalProof};
}
// Update with data (like secp256k1_rfc6979_hmac_sha256_update)
/*
  - add nonce (32 bytes)
  - add commitment point (conf val) (33 bytes)
  - add genp (33 bytes)
  - add var len message

  */
// hmac.update("jjh");

// Finalize (like secp256k1_rfc6979_hmac_sha256_finalize)
// return hmac.digest('hex');

/* For proof I need to
- have existing 
- add 'signs' of first commit pubkey in each ring
- add first commit pubkey of each ring (32 bytes since 1 byte for signs)
- stores e0 in 32 bytes (aka the last msg hash)
- add each ring sig in a flattened row to buffer


message hash needs
- commit
- genP
- proof (right b4 genrand)
- first commit point of every ring
- Thats it!

*/

/*
  1) Take a regtest tx
  2) parse liquid tx
  2) Extract the nonce and range proof, blinding key, script?
  3) Get nonce by multiplying ephemeral key ((nonce_commitment.vchCommitment) with our priv key 

  */

// Reset change
let nonceArg =
  0x5e9327655ce0ee21dc4f7ec1cbdcc5e393973e4d2a407b01a69068e94bde90a1n;

// Reset change
// commit
// commit
// commit
let commitXArr = [
  1572034863924652n,
  855152059326233n,
  975457184466495n,
  408441583636078n,
  8718917558778n,
];

let commitYArr = [
  14660813141304632n,
  16813475458067060n,
  13520591078439290n,
  16854752544074295n,
  1052500369865187n,
];

// genP
let genPXArr = [
  3698275472572113n,
  960805623148293n,
  1361606309141106n,
  2269370551941167n,
  95069322382348n,
];

let genPYArr = [
  90476339017378n,
  3910324583965771n,
  966802187916966n,
  1105471236702902n,
  117776083589745n,
];

// let kArr = [17187201580510244500n, 17315889039600401204n, 16388465764006301260n,
//     11978092259031919847n];

// Reset Change
let ephemeralOutputBlindArg =
  0xab8b1b80a73864094b435de7ee3a1f52ffea6957fb4bdc2d7b3b9f22eb2a5e35n;

let commitX = Fn.create(arrToPoint(commitXArr));
let commitY = Fp.create(arrToPoint(commitYArr));
let commitPoint = new schnorr.Point(commitX, commitY, Fp.ONE);
commitPoint.assertValidity();

let genPX = Fn.create(arrToPoint(genPXArr));
let genPY = Fp.create(arrToPoint(genPYArr));
let genP = new schnorr.Point(genPX, genPY, Fp.ONE);
genP.assertValidity();

let serializedPointArg = commitPoint.toBytes(true);
try {
  Fp.sqrt(commitPoint.y);
  serializedPointArg[0] = 0;
} catch (e) {
  serializedPointArg[0] = 1;
}

let serializedGenPArg = genP.toBytes(true);

//re-assess sqrt
try {
  Fp.sqrt(genP.y);
  serializedGenPArg[0] = 0;
} catch (e) {
  serializedGenPArg[0] = 1;
}

//Reset
// the value we use is 'value - 1'
let valueBigIntArg: bigint = BigInt(0x0000000005f5e0ff); //bytesToNumberBE(value);

// Reset
// This is the scriptpubkey of output
let extraCommitBuffer = Buffer.from(
  "0014fd27b2a4f9c9ea6c6a1bafdd1a3d1615d3fbd47d",
  "hex"
) as Uint8Array;

const assetId =
  "25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a";
const assetBlind =
  "0a4fc39109a3899d425eed8911f158c665f9e7bec05f20af760bde0fe776a381";

// let nonce2 = 0x0n;
// let serializedPoint2 = 0;
// let serializedGenP2 = 0;

// let decryptionKeys = genrand(
//     nonce2,
//     serializedPoint2,
//     serializedGenP2,
//     new Uint8Array(Array(3328).fill(0)),
//   );

// generateRangeProof.bind(this)(
//   serializedPointArg,
//   serializedGenPArg,
//   ephemeralOutputBlindArg,
//   nonceArg,
//   valueBigIntArg,
//   extraCommitBuffer,
//   assetId,
//   assetBlind
// );
