import { CurvePoint } from "@noble/curves/abstract/curve";
import { invert } from "@noble/curves/abstract/modular";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, randomBytes } from "@noble/hashes/utils";

export const toBytes = secp256k1.Point.Fn.toBytes;
export const hasEven = (y: bigint) => y % BigInt(2) === BigInt(0);
export const Fn = secp256k1.Point.Fn;
export const Fp = secp256k1.Point.Fp;
export const { lift_x } = schnorr.utils;
export const G = secp256k1.Point.BASE;
export const num = bytesToNumberBE;
export const invert2 = invert;

export function generatePublicKeySignature(
  P: CurvePoint<any, any>,
  messageHash: bigint,
  sPartOfSig: Uint8Array
): {
  noncePoint: CurvePoint<any, any>;
} {
  // const P = lift_x(Fn.fromBytes(xOnlyPubkey));

  /* Changed from '-' to '+' to match the cool kids. 
  The original paper seems inconsistent and uses '-' for signing and '+' for verification,
  so I originally changed the verification process to match the signing process in the paper. 
  Now I'm changing the signing process to match the verification process in the paper.
  REF:
    - https://github.com/BlockstreamResearch/secp256k1-zkp/blob/6152622613fdf1c5af6f31f74c427c4e9ee120ce/src/modules/rangeproof/borromean_impl.h#L148
    - https://github.com/blockchain-research/crypto/blob/7a084ae2ca5ae0dc1a96aa86e42f01d8d7e4817a/brs/brs.go#L158
  */
  // R = s*G + eP
  let sG = G.multiply(Fn.fromBytes(sPartOfSig));
  let eP = P.multiply(messageHash);
  let R = sG.add(eP);

  //sanity check
  let V1 = R.add(eP.negate());
  if (!V1.equals(sG)) {
    throw new Error("Signature generation broken.");
  }

  return {
    noncePoint: R,
  };
}

export function signPartOne(
  signerNoncePoint: Uint8Array,
  message: Uint8Array,
  ringIndex: number,
  signerIndex: number,
  pubkeys: CurvePoint<any, any>[],
  s: Uint8Array[][]
) {
  let ringNonces: Uint8Array[] = [];
  // let reconstuctedPoint = lift_x(Fn.fromBytes(signerNoncePoint.subarray(1)))
  // signerNoncePoint = reconstuctedPoint.negate().toBytes()
  ringNonces.push(signerNoncePoint);

  // let signerMessagePreimage = signerNoncePoint;

  // let signerGeneratedMessageHash = Fn.fromBytes(sha256(signerMessagePreimage));

  if (s[ringIndex].length != pubkeys.length) {
    throw new Error("signature array must equal pubkey array length");
  }

  let currentMessageHash = signerNoncePoint;
  let noncePoint: CurvePoint<any, any> | undefined;

  //For every index after the signer's
  for (let j = signerIndex + 1; j < pubkeys.length; j++) {
    let currentMessagePreimage = concatBytes(
      noncePoint ? noncePoint?.toBytes() : signerNoncePoint,
      message,
      numberToBytesBE(ringIndex, 4),
      numberToBytesBE(j, 4)
    );
    currentMessageHash = sha256(currentMessagePreimage);

    noncePoint = generatePublicKeySignature(
      pubkeys[j],
      Fp.fromBytes(currentMessageHash),
      s[ringIndex][j]
    ).noncePoint;

    ringNonces.push(noncePoint.toBytes());
    currentMessageHash = noncePoint.toBytes();
  }

  // currentMessageHash = Buffer.from(Fn.fromBytes(currentMessageHash.subarray(1)).toString(16)) as Uint8Array

  return {
    lastRingNonce: ringNonces[ringNonces.length - 1],
    lastMessageHash: currentMessageHash,
  };
}

export function signPartTwo(
  signerNoncePoint: Uint8Array,
  message: Uint8Array,
  ringIndex: number,
  signerIndex: number,
  pubkeys: CurvePoint<any, any>[],
  s: Uint8Array[][]
) {
  let ringNonces: Uint8Array[] = [];
  // let reconstuctedPoint = lift_x(Fn.fromBytes(signerNoncePoint.subarray(1)))
  // signerNoncePoint = reconstuctedPoint.negate().toBytes()
  ringNonces.push(signerNoncePoint);

  // let signerMessagePreimage = signerNoncePoint;

  // let signerGeneratedMessageHash = Fn.fromBytes(sha256(signerMessagePreimage));

  if (s[ringIndex].length != pubkeys.length) {
    throw new Error("signature array must equal pubkey array length");
  }

  let currentMessageHash = signerNoncePoint;
  let noncePoint: CurvePoint<any, any> | undefined;

  //For every index after the signer's
  for (let j = signerIndex + 1; j < pubkeys.length; j++) {
    let currentMessagePreimage = concatBytes(
      noncePoint ? noncePoint?.toBytes() : signerNoncePoint,
      message,
      numberToBytesBE(ringIndex, 4),
      numberToBytesBE(j, 4)
    );
    currentMessageHash = sha256(currentMessagePreimage);

    noncePoint = generatePublicKeySignature(
      pubkeys[j],
      Fp.fromBytes(currentMessageHash),
      s[ringIndex][j]
    ).noncePoint;

    ringNonces.push(noncePoint.toBytes());
    currentMessageHash = noncePoint.toBytes();
  }

  // currentMessageHash = Buffer.from(Fn.fromBytes(currentMessageHash.subarray(1)).toString(16)) as Uint8Array

  return {
    lastRingNonce: ringNonces[ringNonces.length - 1],
    lastMessageHash: currentMessageHash,
  };
}

export function generatePublicKeysForRing(
  ringSize: number,
  signerIndex: number,
  signerPublicKey: Uint8Array
) {
  let pubkeys: Uint8Array[] = [];
  for (let i = 0; i < ringSize; i++) {
    const ephemeralSecret = secp256k1.utils.randomSecretKey();
    let ephemeralPub =
      i === signerIndex
        ? signerPublicKey
        : secp256k1.getPublicKey(ephemeralSecret);

    if (
      i != signerIndex &&
      !hasEven(secp256k1.Point.fromBytes(ephemeralPub).y)
    ) {
      ephemeralPub = secp256k1.getPublicKey(
        Fn.create(-Fn.fromBytes(ephemeralSecret))
      );
    }

    pubkeys.push(ephemeralPub);
  }

  return pubkeys;
}

// Think of this as splitting the value into 2 bit chunks
// and putting each chunk in a different index of secidx
export function getSecIdx(valueBigIntArg: bigint) {
  let secidx: any[] = [];
  for (let i = 0; i < 26; i++) {
    secidx[i] = Number(valueBigIntArg >> BigInt(i * 2)) & 3;
  }

  return secidx;
}
