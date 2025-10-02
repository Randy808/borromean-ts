import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/utils";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, randomBytes } from "@noble/hashes/utils";
import crypto from 'crypto';

// This mimics the initialization step
function hmacSha256Initialize(key: string): crypto.Hmac {
  return crypto.createHmac('sha256', key);
}

export const toBytes = secp256k1.Point.Fn.toBytes;
export const hasEven = (y: bigint) => y % BigInt(2) === BigInt(0);
export const Fn = secp256k1.Point.Fn;
export const Fp = secp256k1.Point.Fp;
export const { lift_x } = schnorr.utils;
export const G = secp256k1.Point.BASE;
export const num = bytesToNumberBE;

// THERE ARE 26 RINGS EACH WITH 4 ELEMENTS BECAUSE BASE OF RANGE PROOF IS 4

// let xArr = [3650910716759624n, 2604924097457903n, 4278302820861390n, 2756423381355228n, 155132965742611n]
// xArr.reduce((acc, curr, i) => {
//     return acc + (curr << BigInt(i)*52n)
// })
//let xO = 63818000530055485660398688976806071014636037844666496062306599376195508309576n

// let yArr = [3055165646473930n, 914657391758022n, 4314816676357541n, 2617411613428732n, 74803742707544n]
// yArr.reduce((acc, curr, i) => {
//     return acc + (curr << BigInt(i)*52n)
// })
//let yO = 30772474882486885187329123848462996678761778465280534878633592171742304307914n

// //sum(i=0..4, f.n[i] << (i*52))
// arr.reduce((acc, curr, i) => {
//     return acc + (curr << BigInt(i)*52n)
// })

let x = 63818000530055485660398688976806071014636037844666496062306599376195508309576n

let n = Fp.create(x)
let point = lift_x(n);
console.log(point)

let nonce = 0xfd5dbffd6fc38d513bf309319aabda0b4e1a88b473ca5736a4287e090fd8597b

//    secp256k1_scalar s[128];     /* Signatures in our proof, most forged. */
// Each element is 4 numbers

const hmac = hmacSha256Initialize("tes");
  
  // Update with data (like secp256k1_rfc6979_hmac_sha256_update)
  /*
  - add nonce (32 bytes)
  - add commitment point (conf val) (33 bytes)
  - add genp (33 bytes)
  - add var len message

  */
  hmac.update("jjh");
  
  // Finalize (like secp256k1_rfc6979_hmac_sha256_finalize)  
  // return hmac.digest('hex');



  /*
  1) Take a regtest tx
  2) parse liquid tx
  2) Extract the nonce and range proof, blinding key, script?
  3) Get nonce by multiplying ephemeral key ((nonce_commitment.vchCommitment) with our priv key 

  */