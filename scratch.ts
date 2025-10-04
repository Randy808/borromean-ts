import { schnorr } from "@noble/curves/secp256k1";
import { Fn } from "./utils";

let arrToPoint = (arr: Array<bigint>): bigint => {
  return arr.reduce((acc: bigint, curr, i: number): bigint => {
    return acc + (BigInt(curr) << (BigInt(i) * BigInt(52)));
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

let x = jacobianArrToProjectivePoint(
  [
    2237712096142064n,
    6118543680428061n,
    5661755893269285n,
    5093000537889386n,
    185517524850791n,
  ],
  [
    20319635515123069n,
    19669292734376138n,
    19017741244279886n,
    18639694936018407n,
    1127062039601232n,
  ],
  [
    3578244923336438n,
    1150374887650552n,
    4227050510168899n,
    1537668810532209n,
    166168209568631n,
  ]
);

let genPx = arrToPoint([
  14493328530442n,
  3798737458865307n,
  2485056678854474n,
  3359337944824989n,
  106523285574344n,
]);

// console.log(genPx)

// debugger
// console.log(x)

let arrToScalar = (arr: Array<bigint>): bigint => {
  return arr.reduce((acc: bigint, curr, i: number): bigint => {
    acc = acc + (BigInt(curr) << (BigInt(i) * 64n));
    // console.log("not hex:", acc)
    // console.log("hex", Buffer.from(acc.toString(16), "hex").toString("hex"))
    return acc;
  }, 0n);
};


console.log(arrToPoint([
2371269361520435n, 196920563370754n, 4137252736472029n, 
      2382499598168164n, 63939177161758n
]).toString(16))

/*3a26fff1241e876deea39f064eb2cf37b413dd0b319243a8b0286ca82bf5cf33

To reset state

This is asset id and genP
x/64b message


This is the value that will be encoded (actually value - 1):
p/x v


Prep is asset_id, blind, and value after ths line:
prep[8 + i + idx] = prep[16 + i + idx] = prep[24 + i + idx] = (v >> (56 - i * 8)) & 255;


275 is genrand breakpoint


Get nonce:
x/32b nonce

commit:
p *commit

genP:
p *genp

blind:
x/32b blind




commit
{x = {n = {2605682607844813, 3959471973488376, 392473779877948, 
      3676170069033022, 203914897534784}}, y = {n = {16775956830140505, 
      13519137163124838, 15789025010901419, 17404743654562461, 
      1055172890589396}}


genp
{x = {n = {14493328530442, 3798737458865307, 2485056678854474, 
      3359337944824989, 106523285574344}}, y = {n = {2961459019530422, 
      1277607914326066, 2455117097591148, 473051163415351, 43552662608318}}, 
  infinity = 0}
*/
