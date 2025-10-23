import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, toBytes } from "@noble/hashes/utils";
import crypto from "crypto";
import { CurvePoint } from "@noble/curves/abstract/curve";
import getMessage from "./message";
import { secp256k1_borromean_sign } from ".";

// Constants
const NUM_RINGS = 26;
const LAST_RING_INDEX = NUM_RINGS - 1;
const STANDARD_RING_SIZE = 4;
const ENCRYPTION_CHUNK_SIZE = 32;
const HMAC_OUTPUT_SIZE = 32;

// Proof header configuration
const PROOF_HEADER = (() => {
  const header = new Uint8Array(10);
  header[0] = 0x60;
  header[1] = 0x33;
  header[9] = 0x01;
  return header;
})();

// Re-exports
export const toBytesFn = secp256k1.Point.Fn.toBytes;
export const hasEven = (y: bigint) => y % BigInt(2) === BigInt(0);
export const Fn = secp256k1.Point.Fn;
export const Fp = secp256k1.Point.Fp;
export const { lift_x } = schnorr.utils;
export const G = secp256k1.Point.BASE;
export const num = bytesToNumberBE;

// Types
interface RFC6979RNG {
  v: Buffer;
  k: Buffer;
  retry: number;
}

// Helper functions
function hmacSha256(key: Buffer, ...data: Buffer[]): Buffer {
  const hmac = crypto.createHmac("sha256", key);
  data.forEach((chunk) => hmac.update(chunk));
  return hmac.digest();
}

function initializeRFC6979HMAC(key: Buffer): RFC6979RNG {
  const rng: RFC6979RNG = {
    v: Buffer.alloc(HMAC_OUTPUT_SIZE, 0x01),
    k: Buffer.alloc(HMAC_OUTPUT_SIZE, 0x00),
    retry: 0,
  };

  const zero = Buffer.from([0x00]);
  const one = Buffer.from([0x01]);

  // RFC6979 3.2.d
  rng.k = hmacSha256(rng.k, rng.v, zero, key);
  rng.v = hmacSha256(rng.k, rng.v);

  // RFC6979 3.2.f
  rng.k = hmacSha256(rng.k, rng.v, one, key);
  rng.v = hmacSha256(rng.k, rng.v);

  return rng;
}

function generateRFC6979HMAC(rng: RFC6979RNG, outputLength: number): Buffer {
  // RFC6979 3.2.h
  const zero = Buffer.from([0x00]);

  if (rng.retry) {
    rng.k = hmacSha256(rng.k, rng.v, zero);
    rng.v = hmacSha256(rng.k, rng.v);
  }

  const output = Buffer.alloc(outputLength);
  let offset = 0;
  let remaining = outputLength;

  while (remaining > 0) {
    rng.v = hmacSha256(rng.k, rng.v);
    const bytesToCopy = Math.min(remaining, HMAC_OUTPUT_SIZE);
    rng.v.copy(output, offset, 0, bytesToCopy);
    offset += bytesToCopy;
    remaining -= bytesToCopy;
  }

  rng.retry = 1;
  return output;
}

function xorEncryptMessage(
  message: Uint8Array,
  key: Buffer,
  ringIndex: number,
  elementIndex: number
): void {
  const offset =
    (ringIndex * STANDARD_RING_SIZE + elementIndex) * ENCRYPTION_CHUNK_SIZE;
  for (let b = 0; b < ENCRYPTION_CHUNK_SIZE; b++) {
    key[b] ^= message[offset + b];
    message[offset + b] = key[b];
  }
}

export function getQuadness(pubkey: CurvePoint<any, any>): number {
  try {
    Fp.sqrt(pubkey.y);
    return 0;
  } catch (e) {
    return 1;
  }
}

function createHMACKey(
  nonce: bigint,
  commitment: Uint8Array,
  serializedGenP: Uint8Array
): Buffer {
  return Buffer.concat([
    toBytesFn(nonce),
    commitment,
    serializedGenP,
    PROOF_HEADER,
  ]);
}

function generateSecretIndices(value: bigint): number[] {
  const indices: number[] = [];
  for (let i = 0; i < NUM_RINGS; i++) {
    indices[i] = Number(value >> BigInt(i * 2)) & 3;
  }
  return indices;
}

function expandRingPublicKeys(
  initialPoints: CurvePoint<any, any>[],
  negativeGenP: CurvePoint<any, any>
): CurvePoint<any, any>[][] {
  const expanded: CurvePoint<any, any>[][] = [];
  let currentNegativeGenP = negativeGenP;

  for (let i = 0; i < NUM_RINGS; i++) {
    expanded[i] = [initialPoints[i]];

    for (let j = 1; j < STANDARD_RING_SIZE; j++) {
      expanded[i].push(expanded[i][j - 1].add(currentNegativeGenP));
    }

    currentNegativeGenP = currentNegativeGenP.multiply(4n);
  }

  return expanded;
}

function serializeRingPublicKeys(
  publicKeys: CurvePoint<any, any>[][]
): Uint8Array[] {
  const serialized: Uint8Array[] = [];

  for (let i = 0; i < NUM_RINGS - 1; i++) {
    const serializedKey = publicKeys[i][0].toBytes();
    serializedKey[0] = getQuadness(publicKeys[i][0]);
    serialized.push(serializedKey);
  }

  return serialized;
}

function createSignsBuffer(publicKeys: CurvePoint<any, any>[][]): Uint8Array {
  const bufferSize = Math.ceil(NUM_RINGS / 8);
  const signs = new Uint8Array(bufferSize);

  for (let i = 0; i < NUM_RINGS - 1; i++) {
    const byteIndex = Math.floor(i / 8);
    const bitPosition = i % 8;
    signs[byteIndex] |= getQuadness(publicKeys[i][0]) << bitPosition;
  }

  return signs;
}

export function genrand(
  nonce: bigint,
  commitVal: Uint8Array,
  serializedGenPS: Uint8Array,
  message: Uint8Array
): Buffer[] {
  const hmacKey = createHMACKey(nonce, commitVal, serializedGenPS);
  const rng = initializeRFC6979HMAC(hmacKey);
  const decryptionKeys: Buffer[] = [];

  for (let i = 0; i < NUM_RINGS; i++) {
    if (i !== LAST_RING_INDEX) {
      generateRFC6979HMAC(rng, HMAC_OUTPUT_SIZE); // Advance RNG
      generateRFC6979HMAC(rng, HMAC_OUTPUT_SIZE); // Skip secret generation
    }

    for (let j = 0; j < STANDARD_RING_SIZE; j++) {
      const key = generateRFC6979HMAC(rng, HMAC_OUTPUT_SIZE);

      if (message) {
        xorEncryptMessage(message, key, i, j);
      }

      decryptionKeys.push(key);
    }
  }

  return decryptionKeys;
}

export function generateRangeProof(
  serializedPoint: Uint8Array,
  serializedGenP: Uint8Array,
  ephemeralOutputBlind: bigint,
  nonce: bigint,
  valueB: bigint,
  extraCommit: Uint8Array,
  assetId: string,
  assetBlind: string,
  genP: CurvePoint<any, any>
): { finalProof: Uint8Array } {
  const hmacKey = createHMACKey(nonce, serializedPoint, serializedGenP);
  const rng = initializeRFC6979HMAC(hmacKey);

  // Generate secret indices from value
  const secretIndices = generateSecretIndices(valueB);

  // Generate message
  const valueHex = Buffer.from(numberToBytesBE(valueB, 8)).toString("hex");
  const message = getMessage(
    NUM_RINGS,
    STANDARD_RING_SIZE,
    assetId,
    assetBlind,
    valueHex,
    secretIndices[LAST_RING_INDEX] === STANDARD_RING_SIZE - 1,
    "hello world"
  );

  // Generate secrets and signatures
  const secrets: Buffer[] = [];
  const signatures: Buffer[][] = [];
  const nonces: Buffer[] = [];
  let accumulator = 0n;

  for (let i = 0; i < NUM_RINGS; i++) {
    signatures[i] = [];

    // Generate secret for this ring
    if (i !== LAST_RING_INDEX) {
      generateRFC6979HMAC(rng, HMAC_OUTPUT_SIZE); // Advance RNG
      const secret = generateRFC6979HMAC(rng, HMAC_OUTPUT_SIZE);
      secrets.push(secret);
      accumulator += BigInt("0x" + secret.toString("hex"));
      // TODO: Add overflow and zero checks with retry logic
    } else {
      const negativeSum = Fn.create(0n - accumulator);
      secrets.push(Buffer.from(negativeSum.toString(16), "hex"));
    }

    // Generate signatures for this ring
    for (let j = 0; j < STANDARD_RING_SIZE; j++) {
      const sig = generateRFC6979HMAC(rng, HMAC_OUTPUT_SIZE);

      if (message) {
        xorEncryptMessage(message, sig, i, j);
      }

      signatures[i].push(sig);
    }
  }

  // Extract nonces and zero out signature slots
  for (let i = 0; i < NUM_RINGS; i++) {
    nonces.push(signatures[i][secretIndices[i]]);
    signatures[i][secretIndices[i]] = Buffer.alloc(HMAC_OUTPUT_SIZE);
  }

  // Adjust last secret with ephemeral blind
  const sumOfBlindAndLastPartialBlind =
    Fn.fromBytes(secrets[secrets.length - 1]) + ephemeralOutputBlind;
  secrets[secrets.length - 1] = Buffer.from(
    Fn.toBytes(Fn.create(sumOfBlindAndLastPartialBlind))
  );

  // Generate initial public keys
  const initialPublicKeys: CurvePoint<any, any>[] = [];

  for (let i = 0; i < NUM_RINGS; i++) {
    const bG = G.multiply(Fn.fromBytes(secrets[i]));
    const vValue = BigInt(secretIndices[i]) << (BigInt(i) * 2n);

    const commitmentPoint =
      vValue === 0n ? bG : bG.add(genP.multiply(Fn.create(vValue)));

    initialPublicKeys.push(commitmentPoint);
  }

  // Expand ring public keys
  const publicKeys = expandRingPublicKeys(initialPublicKeys, genP.negate());

  // Serialize ring public keys for message
  const serializedRingKeys = serializeRingPublicKeys(publicKeys);

  // Create message for signature
  const messagePreimage = concatBytes(
    serializedPoint,
    serializedGenP,
    PROOF_HEADER,
    ...(serializedRingKeys as Uint8Array[]),
    extraCommit
  );
  const messageHash = sha256(messagePreimage);

  // Generate Borromean ring signature
  const { sharedRootMessageHash: e0 } = secp256k1_borromean_sign(
    signatures as any,
    publicKeys,
    nonces,
    secrets,
    secretIndices,
    NUM_RINGS,
    messageHash
  );

  // Create signs buffer
  const signs = createSignsBuffer(publicKeys);

  // Serialize commitments (exclude first byte which is the sign)
  const commitmentBuffer = serializedRingKeys.reduce(
    (acc, val) => concatBytes(acc, val.subarray(1)),
    new Uint8Array()
  );

  // Serialize signatures
  const signatureBuffer: Uint8Array = signatures.reduce((acc, sigArray) => {
    const serializedSigs = sigArray.reduce(
      (acc2, sig) => concatBytes(acc2, sig),
      new Uint8Array() as Uint8Array
    );
    return concatBytes(acc, serializedSigs);
  }, new Uint8Array() as Uint8Array);

  // Construct final proof
  const finalProof = concatBytes(
    PROOF_HEADER, // 10 bytes
    signs, // 4 bytes
    commitmentBuffer, // 800 bytes
    Fn.toBytes(e0!), // 32 bytes
    signatureBuffer // 3328 bytes
  );

  return { finalProof };
}

// Legacy export
export function arrToPoint(arr: Array<bigint>): bigint {
  return arr.reduce((acc, curr, i) => {
    return acc + (BigInt(curr) << (BigInt(i) * BigInt(52)));
  }, 0n);
}
