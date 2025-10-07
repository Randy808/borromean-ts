import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/utils";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, randomBytes, toBytes } from "@noble/hashes/utils";
import crypto from "crypto";

// Reset change
import messageBytes from "./message";
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

let proof = new Array(10).fill(0).reduce((acc: Buffer, n) => {
  return Buffer.from([...acc, n]);
}, Buffer.from([]));

proof[0] = 0x60;
proof[1] = 0x33;
proof[9] = 0x01;

function generateRangeProof(
  serializedPoint: Uint8Array,
  serializedGenP: Uint8Array,
  blind: bigint,
  nonce: bigint,
  valueB: bigint,
  messageHashForSignature: Buffer
) {
  let pubs: CurvePoint<any, any>[][] = [];

  let hmacKey = Buffer.concat([
    toBytesFn(nonce),
    serializedPoint,
    serializedGenP,
    new Uint8Array(proof),
  ]);

  const rng = secp256k1_rfc6979_hmac_sha256_initialize(hmacKey);

  const NUM_RINGS = 26;
  const STANDRAD_RING_SIZE = 4;

  let sec: any[] = [];

  let message = messageBytes;

  const LAST_RING_INDEX = NUM_RINGS - 1;
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
          if (i == LAST_RING_INDEX && j === 0) {
            console.log(
              (
                tmp[b] ^
                message[
                  (i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b
                ]
              ).toString(16)
            );
          }

          // if (i == LAST_RING_INDEX && j === STANDRAD_RING_SIZE - 1 && b == 10) {
          //   console.log("--");
          //   debugger;
          // }
          tmp[b] ^=
            message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b];
          message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b] =
            tmp[b];
        }
      }

      sigs[i].push(tmp);
    }
  }

  let secidx: any[] = [];
  let k: any[] = [];

  for (let i = 0; i < NUM_RINGS; i++) {
    secidx[i] = Number(valueB >> BigInt(i * 2)) & 3;
    k.push(sigs[i][secidx[i]]);
    sigs[i][secidx[i]] = Buffer.from(Array(32).fill(0)) as Uint8Array;
  }

  let sumOfBlindAndLastPartialBlind = Fn.fromBytes(sec[sec.length - 1]) + blind;
  sec[sec.length - 1] = Fn.toBytes(Fp.create(sumOfBlindAndLastPartialBlind));

  // TODO: Allocate NUM_RINGS spaces for sings in proof

  for (let i = 0; i < NUM_RINGS; i++) {
    // secp256k1_pedersen_ecmult(ecmult_gen_ctx, &pubs[npub], &sec[i], ((uint64_t)secidx[i] * scale) << (i*2), genp);
    let bG = G.multiply(Fn.fromBytes(sec[i]));
    // let bG2 = lift_x(Fn.fromBytes(sec[i])); // Makes a new point L

    let vValue = BigInt(BigInt(secidx[i]) << (BigInt(i) * 2n));

    if (vValue === 0n) {
      pubs[i] = [bG];
      continue;
    }

    // TODO: Make sure we take in whole value for genP so we can pick correct quadness/parity
    let vP = genP.multiply(Fn.create(vValue));

    let vPWithbG = bG.add(vP);
    //TODO: Write 'quadness' to reserved space in proof
    pubs[i] = [vPWithbG];
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

  //RESET
  let extraCommit = "001466f05bc559d7e0d8471c703089d79e582fdd731b";

  let messagePreimage = concatBytes(
      serializedPoint,
      serializedGenP,
      proof as Uint8Array,
      ...ringPubkeysForMessage,
      Buffer.from(extraCommit, "hex") as Uint8Array
    )

  let messageH = sha256(
    messagePreimage
  );

  //last pub
  // x f05833effa5f745e5999d84494fd6812474fc0872f00a0765b9149d6448f92d105335b77fdfe5
  // y 9374c7456160001b94d77e5ce908000434cc1ef90fb7000a512852dd189200105335b77fdfe5

  console.log("sec: " + Buffer.from(sec[LAST_RING_INDEX]).toString("hex"));
  secp256k1_borromean_sign(
    sigs,
    pubs,
    k,
    sec,
    secidx,
    NUM_RINGS,
    messageHashForSignature
  );

  console.log();
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
  0xc5fa60ee454f208a379662fb31302d3caefc72d40919ed4ab58b511e57f2d40an;

// Reset change
// commit
// commit
// commit
let commitXArr = [
  1714103949332285n,
  879411113475107n,
  2963786728296436n,
  3815466249912002n,
  228220164417948n
];

let commitYArr = [
  16764925268671686n,
  14310197772141882n,
  14836082064650123n,
  17142388246015281n,
  962893588244796n
];

// genP
let genPXArr = [
  1023526409959635n,
  783448678690483n,
  3394567772643830n,
  656772673364555n,
  43733853461695n
];

let genPYArr = [
  1097129820796756n,
  121470784712267n,
  2529254140013483n,
  4077288318088986n,
  164250798402776n
];

// let kArr = [17187201580510244500n, 17315889039600401204n, 16388465764006301260n,
//     11978092259031919847n];

// Reset Change
let blindArg =
  0x2ab2e5c830353a0d2d4e87e17f40b7e11bcc543c9a64d1e22f8af5b27977ef39n;

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

//Reset
let messageForSignature = Buffer.from(
  "c42c2725c7b9d3184cafc6da719bae4834ed28ede84f1aa6d619ff3605bbd60f",
  "hex"
);
generateRangeProof.bind(this)(
  serializedPointArg,
  serializedGenPArg,
  blindArg,
  nonceArg,
  valueBigIntArg,
  messageForSignature
);
