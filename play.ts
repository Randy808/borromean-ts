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

// This mimics the initialization step
function hmacSha256Initialize(key: Buffer): crypto.Hmac {
  return crypto.createHmac("sha256", new Uint8Array(key));
}
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

function secp256k1_rfc6979_hmac_sha256_finalize(rng: any) {
  rng.k.fill(0);
  rng.v.fill(0);
  rng.retry = 0;
}

let pubs: CurvePoint<any, any>[][] = [];

let arrToPoint = (arr: Array<bigint>): bigint => {
  return arr.reduce((acc: bigint, curr, i: number): bigint => {
    return acc + (BigInt(curr) << (BigInt(i) * BigInt(52)));
  }, 0n);
};

let arrToScalar = (arr: Array<bigint>): bigint => {
  return arr.reduce((acc: bigint, curr, i: number): bigint => {
    acc = acc + (BigInt(curr) << (BigInt(i) * 64n));
    // console.log("not hex:", acc)
    // console.log("hex", Buffer.from(acc.toString(16), "hex").toString("hex"))
    return acc;
  }, 0n);
};

function jacobianArrToProjectivePoint(
  x_limbs: bigint[],
  y_limbs: bigint[],
  z_limbs: bigint[]
) {
  const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

  // Convert limb arrays to bigints
  const x_jac = arrToPoint(x_limbs);
  const y_jac = arrToPoint(y_limbs);
  const z_jac = arrToPoint(z_limbs);

  // Convert from Jacobian (X, Y, Z) to Projective (X', Y', Z')
  // Jacobian: affine point is (X/Z², Y/Z³)
  // Projective: affine point is (X'/Z', Y'/Z')
  // Conversion: X' = X*Z, Y' = Y*Z², Z' = Z³

  const z2 = (z_jac * z_jac) % p;
  const z3 = (z2 * z_jac) % p;

  const x_proj = (x_jac * z_jac) % p;
  const y_proj = (y_jac * z2) % p;
  const z_proj = z3;

  return new schnorr.Point(
    Fn.create(x_proj),
    Fn.create(y_proj),
    Fn.create(z_proj)
  );
}

export const toBytesFn = secp256k1.Point.Fn.toBytes;
export const hasEven = (y: bigint) => y % BigInt(2) === BigInt(0);
export const Fn = secp256k1.Point.Fn;
export const Fp = secp256k1.Point.Fp;
export const { lift_x } = schnorr.utils;
export const G = secp256k1.Point.BASE;
export const num = bytesToNumberBE;

// Reset change
let nonce = 0xa0d3d438bde2e8dd62e5e6e7588316edb4debdc0120f44484e822ffabf8fad0fn;

// Reset change
// commit
// commit
let commitXArr = [
  0x5f19deb8268a1n,
  0x63f0eb2a8eda1n,
  0xc943c1ea2d15bn,
  0xcb5a921cd1a8n,
  0xcca930036a8bn
];

let commitYArr = [
  0x37bc3c59dc91b4n,
  0x3b96f131882f9bn,
  0x362d8973c34259n,
  0x3b0a2cb1a5c883n,
  0x3da3b188cf72fn
];

// genP
let genPXArr = [
  0xe375e578f387bn,
  0x37ab390b93634n,
  0xc75b7dc7c511cn,
  0xa554894a0714cn,
  0xafc8f534900cn
];

let genPYArr = [
  0x3f36e1a8dfa08n,
  0xc5ebd52d04835n,
  0x9cf10483a099bn,
  0xdc22401bf074n,
  0x23e9f9d513een
];

// let kArr = [17187201580510244500n, 17315889039600401204n, 16388465764006301260n,
//     11978092259031919847n];

// Reset Change
let blind = 0x5644266b1cf1aa16678d099aafb60eb04da7accf673d9af4d48939858d374fe0n;

let commitX = Fn.create(arrToPoint(commitXArr));
let commitY = Fp.create(arrToPoint(commitYArr));
let commitPoint = new schnorr.Point(commitX, commitY, Fp.ONE);
commitPoint.assertValidity();

let genPX = Fn.create(arrToPoint(genPXArr));
let genPY = Fp.create(arrToPoint(genPYArr));
let genP = new schnorr.Point(genPX, genPY, Fp.ONE);
genP.assertValidity();

// let kArrVal = arrToPoint(kArr)
// let kVal2 = Fp.create(kArrVal);
// let kArrX = concatBytes(new Uint8Array(0), new Uint8Array(Buffer.from(kVal2.toString(16), "hex")))
// // let k0 = secp256k1.Point.fromBytes(toBytesFn(kArrX));

let proof = new Array(10).fill(0).reduce((acc: Buffer, n) => {
  return Buffer.from([...acc, n]);
}, Buffer.from([]));

proof[0] = 0x60;
proof[1] = 0x33;
proof[9] = 0x01;
//    secp256k1_scalar s[128];     /* Signatures in our proof, most forged. */
// Each element is 4 numbers

// y is defined in code, so whether we should use 0 or 1 is defined
//Something is not working here; reset
let serializedPoint = commitPoint.toBytes(true);
try {
  Fp.sqrt(commitPoint.y);
  serializedPoint[0] = 0;
} catch (e) {
  serializedPoint[0] = 1;
}

// serializedPoint[0] = 1;

let serializedGenP = genP.toBytes(true);

//re-assess sqrt
try {
  Fp.sqrt(genP.y);
  serializedGenP[0] = 0;
} catch (e) {
  serializedGenP[0] = 1;
}

// serializedGenP[0] = 1;

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

// secp256k1_rfc6979_hmac_sha256_generate(rng, 32);

let message = messageBytes;

const LAST_RING_INDEX = NUM_RINGS - 1;
let acc = 0n;

//NEVER CONVERT THIS TO FP
// let sec0 = [
//   0xb4dad3ce0a3823c2, 0x7efe9e87932df112, 0x4c140671959e3b98,
//   0x7bb4607864ed8d58,
// ];
// let sec1PointVal = arrToPoint(sec0);
// console.log("Manually conver to hex: ", sec1PointVal);
// This will always be wrong??? Don't run it through Fp
// console.log("secp lib sec[0]", Buffer.from(toBytes(sec1X)).toString("hex"));

let sigs: Uint8Array[][] = [];

//secp256k1_rangeproof_genrand

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
              message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b]
            ).toString(16)
          );
        }

        if (i == LAST_RING_INDEX && j === STANDRAD_RING_SIZE - 1 && b == 10) {
          console.log("--")
          debugger;
        }
        tmp[b] ^=
          message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b];
        message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b] =
          tmp[b];
      }
    }

    sigs[i].push(tmp);
  }
}

//Reset
// the value we use is 'value - 1'
let valueBigint: bigint = BigInt(0x0000000005f5e0ff); //bytesToNumberBE(value);

let secidx: any[] = [];
let k: any[] = [];

for (let i = 0; i < NUM_RINGS; i++) {
  secidx[i] = Number(valueBigint >> BigInt(i * 2)) & 3;
  k.push(sigs[i][secidx[i]]);
  sigs[i][secidx[i]] = Buffer.from(Array(32).fill(0)) as Uint8Array;
}

//K SHOULD BE CORRECT NOW

function hexToBigInt(hexString: string) {
  return BigInt(hexString);
}

let sumOfBlindAndLastPartialBlind = Fn.fromBytes(sec[sec.length - 1]) + blind; // console.log(Buffer.from(Fp.toBytes(Fp.create(sumOfBlindAndLastPartialBlind))).toString("hex"));
console.log("imp:", Fp.create(sumOfBlindAndLastPartialBlind));

//bug in noble curves?: 123987258508901206383958640312997630590231229718974802477928059006481587024707n
// no
sec[sec.length - 1] = Fn.toBytes(Fp.create(sumOfBlindAndLastPartialBlind));

// console.log(Buffer.from(referenceVal).toString("hex"))

/*Blind is confirmed. To check I convert one of the scalar values to hex and make sure it's a substring of the serialized hex for sec[sec.length - 1]*/

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
  //lift_x(Fn.fromBytes(secp256k1.utils.randomSecretKey()));
  // let C = H.multiply(Fn.fromBytes(value)).add(G.multiply(Fn.fromBytes(signerPrivateKey)))
  // console.log(i)

  let vPWithbG = bG.add(vP);
  //TODO: Write 'quadness' to reserved space in proof
  pubs[i] = [vPWithbG];
}

// These are the same, its just that the sumPoint has weird padding for hex chars and has a 0 stuck in there somewhere
console.log(Buffer.from(pubs[0][0].toBytes()).toString("hex"));

let negativeGenP = genP.negate();
//secp256k1_rangeproof_pub_expand
for (let i = 0; i < NUM_RINGS; i++) {
  for (let j = 1; j < STANDRAD_RING_SIZE; j++) {
    pubs[i].push((pubs[i][j - 1] as any).add(negativeGenP));
  }
  negativeGenP = negativeGenP.multiply(4n);
}

console.log();

//Reset
let messageForSignature = Buffer.from(
  "c42c2725c7b9d3184cafc6da719bae4834ed28ede84f1aa6d619ff3605bbd60f",
  "hex"
);

//TODO: Look at that special logic using '-=' when setting prep

// Revisit why last sig was wrong
// was 62bd36f29749b407e2531c0e54de2ee3486b1cae01c6166ca45c845e810d17d9, expected e2bd36f29749b407e2531c0e54de2ee3486b1cae01c6166ca45c845e810d17d9
//TODO: Figure out what's wrong here
//Reset (doesnt need reset but I'm putting it here to draw attention)
// sigs[NUM_RINGS - 1][3] = Buffer.from(0xe2bd36f29749b407e2531c0e54de2ee3486b1cae01c6166ca45c845e810d17d9n.toString(16), "hex") as Uint8Array;

console.log("sec: " + Buffer.from(sec[LAST_RING_INDEX]).toString("hex"));
secp256k1_borromean_sign(
  sigs,
  pubs,
  k,
  sec,
  secidx,
  NUM_RINGS,
  messageForSignature
);

console.log();
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

/*
  1) Take a regtest tx
  2) parse liquid tx
  2) Extract the nonce and range proof, blinding key, script?
  3) Get nonce by multiplying ephemeral key ((nonce_commitment.vchCommitment) with our priv key 

  */
