import * as liquid from "liquidjs-lib";
import { Fn, Fp, G, lift_x } from "./utils";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { arrToPoint, generateRangeProof, genrand, getQuadness } from "./play";
import { txhex1, txhex2 } from "./txhex";
import { txhex3 } from "./txhex3";
import { txhex4 } from "./txhex4";
import { invert } from "@noble/curves/abstract/modular";
import { generateRangeProof2 } from "./play-rewind";
import { txhex5 } from "./txhex5";
import { txhex6 } from "./tx6";

function copyBytes(b: Buffer) {
  return Buffer.from(b.toString("hex"), "hex");
}

function decryptByteValues(
  signatures: Uint8Array,
  decryptionKeys: Uint8Array[]
): { decryptedByteValues: number[] } {
  let decryptedByteValues: number[] = [];
  for (let i = 0; i < 3328; i++) {
    let byteNum = i;
    let row = Math.floor(byteNum / 32);
    let index = byteNum % 32;
    decryptedByteValues.push(signatures[i] ^ decryptionKeys[row][index]);
  }

  let decryptedByteValuesBuffer = Buffer.from(decryptedByteValues);

  console.log("DECRYPTED", decryptedByteValuesBuffer.toString("hex"));

  return { decryptedByteValues };
}

//TODO: Take in an spk and a tx, then returns indexes of outputs on the tx that match
// function getOutputIndexes() {
//   return [1];
// }

function main(nonce: bigint, t: liquid.Transaction, outputIndex: number) {
  //reset
  const index = outputIndex;

  function convertParityByteToQuadness(bytes: Uint8Array) {
    if (bytes.length === 0) {
      throw new Error("Bytes cannot be zero-length");
    }

    return (bytes[0] %= 2);
  }

  let serializedPoint = copyBytes(t.outs[index].value);
  convertParityByteToQuadness(serializedPoint);

  let serializedGenP = copyBytes(t.outs[index].asset);
  convertParityByteToQuadness(serializedGenP);

  let genP = lift_x(Fn.fromBytes(serializedGenP.subarray(1)));
  if (getQuadness(genP) != serializedGenP[0]) {
    genP = genP.negate();
  }

  let decryptionKeys: Uint8Array[] = genrand(
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

  let sharedRootMessageHash = Buffer.from(
    t.outs[index].rangeProof!.subarray(814, 814 + 32).toString("hex"),
    "hex"
  );

  let { decryptedByteValues } = decryptByteValues(signatures, decryptionKeys);

  let valueBigIntArg: bigint = BigInt(
    "0x" +
      Buffer.from(
        decryptedByteValues.slice(decryptedByteValues.length - 8)
      ).toString("hex")
  );

  let decryptedByteValuesBuffer = Buffer.from(decryptedByteValues);
  let assetIdHex = decryptedByteValuesBuffer.subarray(0, 32).toString("hex");
  let assetBlind = decryptedByteValuesBuffer.subarray(32, 64).toString("hex");

  let secidx: any[] = [];
  for (let i = 0; i < 26; i++) {
    secidx[i] = Number(valueBigIntArg >> BigInt(i * 2)) & 3;
  }

  let parsedCommitments: any[] = [];

  for (let i = 0; i < 26; i++) {
    parsedCommitments.push(commitments.subarray(i * 32, i * 32 + 32));
  }

  let extraCommitBuffer = copyBytes(t.outs[index].script);

  let { k, es, sec } = generateRangeProof2(
    serializedPoint,
    serializedGenP,
    nonce,
    valueBigIntArg,
    extraCommitBuffer,
    assetIdHex,
    assetBlind,
    sharedRootMessageHash,
    genP
  );

  const lastRing = 25;
  let ind = secidx[lastRing];
  let realSigForLastRing = signatures.subarray(
    lastRing * 4 * 32 + ind * 32,
    lastRing * 4 * 32 + ind * 32 + 32
  );

  let e_i_inverse: bigint = invert(es[es.length - 1], Fn.ORDER);
  let base: bigint = Fn.create(
    Fn.create(Fn.fromBytes(k[lastRing]) - Fn.fromBytes(realSigForLastRing)) *
      e_i_inverse
  );
  let ephemeralOutputBlind = Fn.create(base - Fn.fromBytes(sec[lastRing]));

  let { finalProof: rangeProof } = generateRangeProof(
    serializedPoint,
    serializedGenP,
    ephemeralOutputBlind,
    nonce,
    valueBigIntArg,
    extraCommitBuffer,
    assetIdHex,
    assetBlind,
    genP
  );

  console.log();

  // //t.outs[index].rangeProof!.subarray(846)
  t.outs[index].rangeProof! = Buffer.from(rangeProof);
  console.log("\n\nTXHEX2\n\n", t.toHex());

  return t;
}

function getNonce(
  nonceCommitmentHex: string,
  blindingKey: bigint
): bigint {
  const ecdhNoncePreimage = sha256(
    secp256k1.Point.fromHex(nonceCommitmentHex)
      .multiply(Fn.create(blindingKey))
      .toBytes()
  );

  return BigInt("0x" + Buffer.from(sha256(ecdhNoncePreimage)).toString("hex"));
}

// let t = liquid.Transaction.fromHex(txhex6);
// let index = 1;
// let blindingKey =
//   0x16d0a5cf8a1d8e9c242345a8f036fcc91cb231c043296a845e774ca4dd2bb2ecn;
// let nonce = getNonce(t, 1, t.outs[index].nonce.toString("hex"), blindingKey);
// main(nonce, t, 1);

export { main as modifyRangeProof, getNonce };
