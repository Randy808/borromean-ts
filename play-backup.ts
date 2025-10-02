import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/utils";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, randomBytes, toBytes } from "@noble/hashes/utils";
import crypto from "crypto";

// Reset change
import messageBytes from "./message";
import { secp256k1_scalar_add } from "./scalar_add";

// This mimics the initialization step
function hmacSha256Initialize(key: Buffer): crypto.Hmac {
  return crypto.createHmac("sha256", new Uint8Array(key));
}

// function getSquareRoot(c: bigint) {
//    let r = 1n;
//   for (let num = c, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
//     // powMod: modular exponentiation.
//     if (e & 1n) r = (r * num) % Fp.ORDER; // Uses exponentiation by squaring.
//     num = (num * num) % P; // Not constant-time.
//   }
//   return Fp.create(r * r) === c ? r : err('sqrt invalid'); // check if result is valid
// }

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














let arrToPoint = (arr: Array<bigint>): bigint => {
  return arr.reduce((acc: bigint, curr, i: number): bigint => {
    return acc + (BigInt(curr) << (BigInt(i) * BigInt(52)));
  }, 0n);
};


let arrToScalar = (arr: Array<bigint>): bigint => {
  return arr.reduce((acc: bigint, curr, i: number): bigint => {
    acc = (acc ) + (BigInt(curr) << (BigInt(i) * 64n));
    // console.log("not hex:", acc)
    // console.log("hex", Buffer.from(acc.toString(16), "hex").toString("hex"))
    return acc;
  }, 0n);
};

export const toBytesFn = secp256k1.Point.Fn.toBytes;
export const hasEven = (y: bigint) => y % BigInt(2) === BigInt(0);
export const Fn = secp256k1.Point.Fn;
export const Fp = secp256k1.Point.Fp;
export const { lift_x } = schnorr.utils;
export const G = secp256k1.Point.BASE;
export const num = bytesToNumberBE;
// export const toBytes = toBytes

//0x6c4428cb0c555b65bac6cad9eace8aa9cacd456619858303fea40b5d915d2a10n;
//0x89bb4a6370b0c6c00c0ac12496469a04ec6ae4f08060f3b83eaf6261667a51b857d68bd8b13a3ac1d41689ffc576890709b12a20f096a68a8f1e08f70ca7acafn

// Reset change
let nonce = 0xb4e72a6c91ff0172139c2f6662599bb5d7303071fbe3f5c473168e2ca23613ffn;

// Reset change
let commitXArr = [
  4397645534016920n, 4172179952076711n, 3210921131013609n, 2305192239516287n, 
    13600758087826n
];

// Reset change
let genPXArr = [
  3273433018902227n, 2734694696106624n, 343330453464879n, 1451061408294925n, 
    193808419624994n
];

// let kArr = [17187201580510244500n, 17315889039600401204n, 16388465764006301260n, 
//     11978092259031919847n];

// Reset Change
let blind = arrToScalar([4516937121746538936n, 17035680262079443896n, 867718241106434564n, 
    9924607994793871040n])//0x89bb4a6370b0c6c00c0ac12496469a04ec6ae4f08060f3b83eaf6261667a51b8n;


    
// Reset Change (verification)
let lastSec = arrToScalar([17698859267875810563n, 563021603379747418n, 6909548301636667037n, 
    5348353402162232515n])

let secondToLastSec = arrToScalar([15808111925838480208n, 6527671231844155421n, 8349664877872557196n, 
    4648515532645326265n])

let commitXVal = arrToPoint(commitXArr);
let commitX = Fn.create(commitXVal);
let point = lift_x(commitX);

let genPVal = arrToPoint(genPXArr);
let genPX = Fn.create(genPVal);
let genP = lift_x(genPX);


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
let serializedPoint = point.toBytes(true);
// try {
//   Fp.sqrt(point.y);
//   serializedPoint[0] = 1;
// } catch (e) {
//   serializedPoint[0] = 0;
// }
serializedPoint[0] = 0;
let serializedGenP = genP.toBytes(true);

//re-assess sqrt
// try {
//   Fp.sqrt(genP.y);
//   serializedGenP[0] = 1;
// } catch (e) {
//   serializedGenP[0] = 0;
// }
serializedGenP[0] = 0;

let hmacKey = Buffer.concat([
  toBytesFn(nonce),
  serializedPoint,
  serializedGenP,
  new Uint8Array(proof),
]);
// let hmacKey2 =
//   toBytes(
//     0xfd5dbffd6fc38d513bf309319aabda0b4e1a88b473ca5736a4287e090fd8597b005ef4e3545b5d34bc22f877392f8f8371b1f4a9d5243a697de0344e2643ef8884014c8fcc96433687d49020e5fb06ea417f2e2afdc0f59a1e25aad2f81a055a284860330000000000000001n
//   );

const rng = secp256k1_rfc6979_hmac_sha256_initialize(hmacKey);

const NUM_RINGS = 26;
const STANDRAD_RING_SIZE = 4;

// let tmp0 = secp256k1_rfc6979_hmac_sha256_generate(rng, 32)
// let tmp2 = secp256k1_rfc6979_hmac_sha256_generate(rng, 32)

// // Should be ce5c91ec885243bf66a24c0ce273775653917fc5870d901b092c8a7ffaf82b45
// console.log(tmp0.toString("hex"))

// // Should be d7cbf9b9b3ba502086e8490d96287ada341e31a19787acb896bd3dfad87695c9
// console.log(tmp2.toString("hex"))
let sec: any[] = [];

// secp256k1_rfc6979_hmac_sha256_generate(rng, 32);

let message = messageBytes;

const LAST_RING_INDEX = NUM_RINGS - 1;
let acc: any = new Uint8Array([]);

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
    acc = secp256k1_scalar_add(acc, tmp).result//BigInt("0x" + tmp.toString("hex"));
    // acc = Fp.create(acc);
    // TODO: Add checks for overflow and 0 and retry when they occur
  } else {
    // TODO: Add blind here
    // see secp256k1_scalar_add(&sec[rings - 1], &sec[rings - 1], &stmp);
    // sec.push(Fp.toBytes(Fp.create(-acc)));
    acc = Fp.fromBytes(acc)
    let negativeSum = Fp.create(0n-acc);
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
        // EVERYTHING IS CORRECT UP TO HERE
        tmp[b] ^=
          message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b];
        message[(i * STANDRAD_RING_SIZE + j) * ENCRYPTION_CHUNK_SIZE + b] =
          tmp[b];
      }
    }

    sigs[i].push(tmp);

    // secp256k1_scalar_set_b32(&s[npub], tmp, &overflow);
    //         ret &= !(overflow || secp256k1_scalar_is_zero(&s[npub]));
    //         npub++;
  }
}

//21
// let H = lift_x(Fn.fromBytes(secp256k1.utils.randomSecretKey()));
// let C = H.multiply(Fn.fromBytes(value)).add(G.multiply(Fn.fromBytes(signerPrivateKey)))

// the value we use is 'value - 1'
let valueBigint: bigint = BigInt(0x00000001004cc429); //bytesToNumberBE(value);

//secidx[i] = (*v >> (i*2)) & 3;
let secidx: any[] = [];
let k: any[] = [];

for (let i = 0; i < NUM_RINGS; i++) {
  secidx[i] = Number(valueBigint >> BigInt(i * 2)) & 3;
  k.push(sigs[i][secidx[i]]);
}

//K SHOULD BE CORRECT NOW

function hexToBigInt(hexString: string) {
  return BigInt(hexString);
}

// sec is 100% correct (I checked sec[0] and sec[24])

debugger;

/*
let r1 = Fp.fromBytes(sec[sec.length - 1]) + blind;
let sumOfBlindAndLastPartialBlind = Fp.create(r1) 

*/
let {result: r1} = secp256k1_scalar_add(sec[sec.length - 1], Buffer.from(blind.toString(16), "hex") as Uint8Array )
let sumOfBlindAndLastPartialBlind = Fp.fromBytes(r1) //secp256k1_scalar_add(Fp.create(hexToBigInt("0x" + Buffer.from(sec[sec.length - 1]).toString("hex"))), Fp.create(blind))
// console.log(Buffer.from(Fp.toBytes(Fp.create(sumOfBlindAndLastPartialBlind))).toString("hex"));
console.log("imp:", Fp.create(sumOfBlindAndLastPartialBlind))
//Buffer.from(this.Fp.toBytes(this.Fp.create(sumOfBlindAndLastPartialBlind))).toString('hex')
//^out: 48de1027b04437f5eae911f1c07923c3b048c0476478ab868a223428efc229ed

sec[sec.length - 1] = Fp.toBytes(Fp.create(sumOfBlindAndLastPartialBlind))

// MANUAL SANITY CHECK OF LAST SEC
let referenceVal = Fp.create(arrToScalar([14423978752022618547n, 13099913795962637847n, 16927080404462674869n, 
    5250651978207606773n]));

  console.log("ref:", referenceVal)

  console.log("\n\n\n")
const blind2 = arrToScalar([4516937121746538936n, 17035680262079443896n, 867718241106434564n, 
    9924607994793871040n])

  console.log("blind:", blind)
  console.log("blind2:", blind2)

  // console.log(Buffer.from(referenceVal).toString("hex"))


  /*Blind is confirmed. To check I convert one of the scalar values to hex and make sure it's a substring of the serialized hex for sec[sec.length - 1]*/

debugger;

/*
$79 = {0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x57, 0xc7, 0x97, 0x2d, 0xec, 0xd3, 0x62, 
  0xdd, 0xe0, 0x8d, 0x1a, 0x84, 0x2c, 0xfa, 0x7, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x0, 
  0x0}
(gdb) n
87                      secp256k1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
(gdb) p/x tmp
$80 = {0xce, 0x5c, 0x91, 0xec, 0x88, 0x52, 0x43, 0xbf, 0x66, 0xa2, 0x4c, 0xc, 0xe2, 0x73, 
  0x77, 0x56, 0x53, 0x91, 0x7f, 0xc5, 0x87, 0xd, 0x90, 0x1b, 0x9, 0x2c, 0x8a, 0x7f, 0xfa, 
  0xf8, 0x2b, 0x45}

*/

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
