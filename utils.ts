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
  noncePoint: WeierstrassPoint<bigint>;
} {
  let sPartOfSig = randomBytes(32);
  const P = lift_x(Fn.fromBytes(xOnlyPubkey));

  // R = s*G + -eP
  let sG = G.multiply(Fn.fromBytes(sPartOfSig));
  let eP = P.multiply(messageHash);
  let R = sG.add(eP.negate());

  let sig = new Uint8Array(64);
  sig.set(toBytes(R.x), 0);
  sig.set(sPartOfSig, 32);

  //sanity check
  let V1 = R.add(eP);
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
  ringNonces.push(toBytes(signerNoncePoint.X));

  let signerMessagePreimage = concatBytes(
    message,
    toBytes(signerNoncePoint.X),
    Fp.toBytes(BigInt(ringIndex)),
    Fp.toBytes(BigInt(signerIndex))
  );

  let signerGeneratedMessageHash = Fn.fromBytes(sha256(signerMessagePreimage));

  let sigs = Array(pubkeys.length);
  let currentMessageHash = signerGeneratedMessageHash;

  //For every index after the signer's
  for (let i = signerIndex + 1; i < pubkeys.length; i++) {
    let { signature, noncePoint } = generatePublicKeySignature(
      pubkeys[i].slice(1),
      currentMessageHash
    );

    currentMessageHash = Fn.fromBytes(
      sha256(
        concatBytes(
          message,
          toBytes(noncePoint.X),
          new Uint8Array([ringIndex]),
          toBytes(BigInt(i))
        )
      )
    );
    sigs[i] = signature;
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
    const ephemeralPub =
      i === signerIndex
        ? signerPublicKey
        : secp256k1.getPublicKey(ephemeralSecret);
    pubkeys.push(ephemeralPub);
  }

  return pubkeys;
}
