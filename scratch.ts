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


console.log(arrToScalar([
8926734743060457137n, 9537975852501016270n, 16057780301889244868n, 
    3447950041500958693n
]).toString(16))
//new e: 5194f98a1973b8c0fb2650231b06ede734b8969e66f019b09fb2c2edcf6c816

//p pubs[14*4] == pubs[14] == 3b4638e3e512b4cb839cdcb1f5e102c0fe7ef953f9b10ba59103093fa83c970e (so 13th one)
//14,0: b98cf3dd2315aaeb224b7fcc4c7bdca662cdcf39bc9a5b08c3a0ddefbe499234
//14, 3: b153a0fbfbaf91b6371b4a657e43fb9d71753600cb56a36aceafd77e12e6e524

//s[4][3] = 7c128b3ac6c1b6b7550f82c756cd150e20de06c946b482b1fa80d32a56177e72 // correct

//s0 4b127598903c02fb708bd522be75ba95706a8981b74bb97413725c3d5fae9b2c
// last sig of first ring should be 0
// second to last of first should be 9aa52550e1d93252424272df694679330f819ac4dc840fb5f99fef7911a8214d


////first sig of last ring 0
//second sig of last ring 6299e1f095e2758c595fda1829045442a2c744ebe1f41464cb2cacd92b5864e7
// 3rd sig last ring 5876d14d4e05f805859aee7625927617120fcce4847151ada12053be54682c77
//last sig e2bd36f29749b407e2531c0e54de2ee3486b1cae01c6166ca45c845e810d17d9

// fourth* ring blind: 8f6473594cec411376620fe057904bf68a29e55cb9c89affb8c429194e58ed92
// last ring blind bfc433c3673a0676e05ebc953bd320c775578f7dc4252039af395f64f6a44f48
// blinds are correct: bfc433c3673a0676e05ebc953bd320c775578f7dc4252039af395f64f6a44f48

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

message hash for borromean right before borromean sign:
x/32b tmp




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



  My ring 14 nonce differs.

  Mine:
Buffer.from(lastRingNonceCollection[14]).toString('hex')
035d2b7fb19b9381b3c2749f9d1324498df58db883427d774605c508b961fbdf0b

  theirs:
0xffff8ef36110: 0x03    0x04    0xcc    0x8f    0x14    0xd0    0x1f    0x97
0xffff8ef36118: 0xee    0x09    0xec    0xe5    0xc8    0x64    0x1c    0x6e
0xffff8ef36120: 0xa1    0x29    0xfc    0xd7    0x64    0x4c    0x96    0xca
0xffff8ef36128: 0xdd    0x01    0x17    0x9b    0xdf    0x0f    0xa3    0xee
0xffff8ef36130: 0xec


sig 14:
aef03b2cffadab2c9618e93a54b51cfaa17dcdb8f668c1eded883db61eca0ec0



 To verify signatures from gdb (replace 20 with desired 'i'):
 p s[20*4 + secidx[20]]
*/
