import * as liquid from "liquidjs-lib";
import { Fn, Fp } from "./utils";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { generateRangeProof, genrand, getQuadness } from "./play";
import { txhex1, txhex2 } from "./txhex";
import { txhex3 } from "./txhex3";
import { txhex4 } from "./txhex4";

function copyBytes(b: Buffer) {
  return Buffer.from(b.toString("hex"), "hex");
}

let t = liquid.Transaction.fromHex(txhex4);

const index = 1;

// Subtracting commt to make pubkeys isnt working?

// console.log("\n\nTXHEX1\n\n", t.toHex());

function convertParityByteToQuadness(bytes: Uint8Array) {
  if (bytes.length === 0) {
    throw new Error("Bytes cannot be zero-length");
  }

  /* I've seen prefix values of 9, 10, and 11. 
  I don't know what format these public keys have been serialized in.
  I've seen a 9 as 1, a 10 as 0, and an 11 as 1.
  Maybe oddness indicates quadness of y?
  */

  // if(bytes[0] >= 10) {
  //   bytes[0] = 0;
  // }
  // else {
  //   bytes[0] = 1;
  // }

  return (bytes[0] %= 2);
}

let blindingKey =
  0x873ef89f7a58ffadb729f1758800b62ab26f898821993f317352eeec284471f6n;
let nonceCommitment = t.outs[index].nonce.toString("hex");

// let blinding = Fn.create(blindingKey)
const ecdhNoncePreimage = sha256(
  secp256k1.Point.fromHex(nonceCommitment).multiply(blindingKey).toBytes()
);

let nonce = BigInt(
  "0x" + Buffer.from(sha256(ecdhNoncePreimage)).toString("hex")
);
// let nonce = BigInt("0x3009f2d6fbd5a965c0356987c9de180303b6e45839e90733e87806fa0f383739");
// let nonce = BigInt("0x1a7e871335bc3c278c5f9f2231689d2d52e5af29a254a40beac6516420d79f3b");
// let serializedPoint = t.outs[index].value.slice();
let serializedPoint = copyBytes(t.outs[index].value);
convertParityByteToQuadness(serializedPoint);

let serializedGenP = copyBytes(t.outs[index].asset);
convertParityByteToQuadness(serializedGenP);

let decryptionKeys = genrand(
  nonce,
  serializedPoint,
  serializedGenP,
  new Uint8Array(Array(3328).fill(0))
);

let signatures = Buffer.from(
  t.outs[index].rangeProof!.subarray(846).toString("hex"),
  "hex"
);

let commitments = Buffer.from(
  t.outs[index].rangeProof!.subarray(14, 814).toString("hex"),
  "hex"
);

// console.log(t)

/*
base offset - 846

3320 bytes for second offset

now we get row as /32*4
/32 for index

*/

let decryptedByteValues: number[] = [];
for (let i = 0; i < 3328; i++) {
  let byteNum = i;
  let row = Math.floor(byteNum / 32);
  let index = byteNum % 32;
  decryptedByteValues.push(signatures[i] ^ decryptionKeys[row][index]);
}

let decryptedByteValuesBuffer = Buffer.from(decryptedByteValues);

console.log("DECRYPTED", decryptedByteValuesBuffer.toString("hex"));

// ADDED
// decryptedByteValuesBuffer[64] = 0x6a
// let decryptedByteValues2: number[] = [];
// for(let i = 0 ; i < 3328; i++) {
//   let byteNum = i;
//   let row = Math.floor(byteNum/(32));
//   let index = byteNum % 32;
//   decryptedByteValues2.push(signatures[i]  ^ decryptionKeys[row][index])
// }
//END_ADDED

// process.exit()

let valueBigIntArg: bigint = BigInt(
  "0x" +
    Buffer.from(
      decryptedByteValues.slice(decryptedByteValues.length - 8)
    ).toString("hex")
); //BigInt(0x0000000005f5e0ff);

//001466f05bc559d7e0d8471c703089d79e582fdd731b
// let extraCommitBuffer = Buffer.from(
//   "0014caea90c0357c99bbf305c7971a2b7e1218a641fd",
//   "hex"
// ) as Uint8Array;

let extraCommitBuffer = copyBytes(t.outs[index].script);

let assetIdHex = decryptedByteValuesBuffer.subarray(0, 32).toString("hex");
let assetBlind = decryptedByteValuesBuffer.subarray(32, 64).toString("hex");

// let bb = Fn.toBytes(Fn.create(blindingKey));

// let b_orig =
//   0xabf582994e1518e46672669d44af3a522fd3c880e094f06fc12a7228549adab4n;


// WHY IS THIS DIFFERENT FROM BLINDING KEY
// Because blind for output is diff from blinding key
// We need a specific blind value so that the sum of blinds equals sum of everything else (both blind and unblind)
let bx =
  Fn.create(
    0xab8b1b80a73864094b435de7ee3a1f52ffea6957fb4bdc2d7b3b9f22eb2a5e35n
  );
// let by =
//   Fp.create(
//     0xab8b1b80a73864094b435de7ee3a1f52ffea6957fb4bdc2d7b3b9f22eb2a5e35n
//   );

  //////

  let secidx: any[] = [];

  for (let i = 0; i < 26; i++) {
    secidx[i] = Number(valueBigIntArg >> BigInt(i * 2)) & 3;
  }

let lastCommitment = commitments.subarray(
  commitments.length - 32,
  commitments.length
);

//valueBigIntArg

//decryptedByteValuesBuffer.subarray(14, 814)
//decryptedByteValuesBuffer.subarray(14, 814).subarray(0, 32)
let rangeProof = generateRangeProof(
  serializedPoint,
  serializedGenP,
  bx,
  nonce,
  valueBigIntArg,
  extraCommitBuffer,
  assetIdHex,
  assetBlind
);

//t.outs[index].rangeProof!.subarray(846)
t.outs[index].rangeProof! = Buffer.from(rangeProof);
console.log("\n\nTXHEX2\n\n", t.toHex());

// fs =""
// for(let i = 8 ; i < 16; i++) {
//   let byteNum = 846 + 3320 + i;
//   let row = Math.floor(byteNum/(32*4));
//   let index = Math.floor(byteNum / 32);
//   fs+=(signatures[i]  ^ decryptionKeys[row - 1][index - 1]).toString(16)
// }

// console.log("\n\n", fs);
