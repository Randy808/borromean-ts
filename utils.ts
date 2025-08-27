import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/utils";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, randomBytes } from "@noble/hashes/utils";

export const toBytes = secp256k1.Point.Fn.toBytes;
export const hasEven = (y: bigint) => y % BigInt(2) === BigInt(0);
export const Fn = secp256k1.Point.Fn;
export const Fp = secp256k1.Point.Fp;
export const { lift_x } = schnorr.utils;
export const G = secp256k1.Point.BASE;
export const num = bytesToNumberBE;

export function generatePublicKeySignature(
  xOnlyPubkey: Uint8Array,
  messageHash: bigint
): {
  signature: Uint8Array;
  noncePoint: any;
} {
  let sPartOfSig = randomBytes(32);
  const P = lift_x(Fn.fromBytes(xOnlyPubkey));

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

  let sig = new Uint8Array(32);
  sig.set(sPartOfSig, 0);

  //sanity check
  let V1 = R.add(eP.negate());
  if (!V1.equals(sG)) {
    throw new Error("Signature generation broken.");
  }

  return {
    signature: sig,
    noncePoint: R,
  };
}

export function signPartOne(
  signerNoncePoint: WeierstrassPoint<bigint>,
  message: Uint8Array,
  ringIndex: number,
  signerIndex: number,
  pubkeys: Uint8Array[]
) {
  let ringNonces: Uint8Array[] = [];
  ringNonces.push(toBytes(signerNoncePoint.x));

  let signerMessagePreimage = concatBytes(
    message,
    toBytes(signerNoncePoint.x),
    new Uint8Array([ringIndex]),
    Fp.toBytes(BigInt(signerIndex))
  );

  let signerGeneratedMessageHash = Fn.fromBytes(sha256(signerMessagePreimage));

  let sigs = Array(pubkeys.length);
  let currentMessageHash = signerGeneratedMessageHash;

  //For every index after the signer's
  for (let j = signerIndex + 1; j < pubkeys.length; j++) {
    let { signature, noncePoint } = generatePublicKeySignature(
      pubkeys[j].slice(1),
      currentMessageHash
    );

    ringNonces.push(toBytes(noncePoint.x));

    currentMessageHash = Fn.fromBytes(
      sha256(
        concatBytes(
          message,
          toBytes(noncePoint.x),
          new Uint8Array([ringIndex]),
          toBytes(BigInt(j))
        )
      )
    );
    sigs[j] = signature;
  }

  return {
    sigs,
    lastRingNonce: ringNonces[ringNonces.length - 1],
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
      ephemeralPub = secp256k1.getPublicKey(Fn.create(-Fn.fromBytes(ephemeralSecret)));
    }

    pubkeys.push(ephemeralPub);
  }

  return pubkeys;
}
