import { schnorr } from "@noble/curves/secp256k1";
import { Fn, Fp } from "./utils";

let arrToPoint = (arr: Array<bigint>): bigint => {
  return arr.reduce((acc: bigint, curr, i: number): bigint => {
    return acc + (BigInt(curr) << (BigInt(i) * BigInt(52)));
  }, 0n);
};

function secp256k1_rfc6979_hmac_sha256_finalize(rng: any) {
  rng.k.fill(0);
  rng.v.fill(0);
  rng.retry = 0;
}

function jacobianArrToProjectivePoint(
  x_limbs: bigint[],
  y_limbs: bigint[],
  z_limbs: bigint[]
) {
  const p: bigint =
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

  // Convert limb arrays to bigints
  const x_jac: bigint = Fp.create(arrToPoint(x_limbs));
  const y_jac: bigint = Fp.create(arrToPoint(y_limbs));
  const z_jac: bigint = Fp.create(arrToPoint(z_limbs));

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
    Fp.create(x_proj),
    Fp.create(y_proj),
    Fp.create(z_proj)
  );
}

let x = jacobianArrToProjectivePoint(
  [
    6559022179227269n,
    12101434511635628n,
    3973194428330131n,
    4552071455300696n,
    494543819241419n,
  ],
  [
    6707771392560515n,
    1553590152907610n,
    6728921688499207n,
    2868590247210216n,
    29940315368786n,
  ],
  [
    1120045385690660n,
    1634561806496662n,
    4086171992858525n,
    4493988155374426n,
    157432496158963n,
  ]
);

// x = {n = {6559022179227269, 12101434511635628, 3973194428330131, 4552071455300696, 494543819241419}}, y = {
//     n = {6707771392560515, 1553590152907610, 6728921688499207, 2868590247210216, 29940315368786}}, z = {n = {
//       1120045385690660, 1634561806496662, 4086171992858525, 4493988155374426, 157432496158963}}, infinity = 0}

// {x = {n = {10709956172225683, 3739047989790743, 7630713595117724,
//       9933580843191355, 776938333682019}}, y = {n = {3015165643765259,
//       4254907030027682, 2138277370120306, 5542852179484277, 103339568709296}},
//   z = {n = {16379539460086, 4002639418001376, 1703615162311230,
//       4203726698761622, 91410432306381}}, infinity = 0}

// console.log(Buffer.from(x.toBytes()).toString("hex"))

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

/*
1088372809714225n, 597984712936334n, 4456497790707510n, 
      2142826917326217n, 263396946050516n
      */

// genp
// console.log(arrToPoint([
// 0x573f5a784671cn, 0x8f28ddff837c8n, 0xda1bb3efc7f52n,
//       0xbbf4dc6b0dec0n, 0xf0661122d999n
// ]).toString(16))

//commit
//p pubs[4]
//702837a04b987b51b87037ff5d90d047097e434c055b53619205dd69e86c39a8
/*
Buffer.from(sigs[0][3]).toString("hex")
'c90239c2c253dca16ccf4c95958d7ac0b3a907a7aefb51a884bde85fdb5066b0'
87c4a3a7580c3cd1b291cf976bf06fb6f1b0b0e6089635b13842259a9ca066ee
*/


/*
good: 44cf06eb4783560929b73025762c9e322e196d76b89801a39847f8202d78d503
vs.
bad: 44cf06eb4783560929b73025762c9e30e8c84a5d67e0a1df581a56adfdaf1a15

referenced value is bigger:
BigInt("0x" + "44cf06eb4783560929b73025762c9e322e196d76b89801a39847f8202d78d503") - BigInt("0x" + "44cf06eb4783560929b73025762c9e30e8c84a5d67e0a1df581a56adfdaf1a15")
= 432420386565659656852420866390673177326n


In Fp:
BigInt("0x" + sec[sec.length - 1].toString("hex")) - BigInt("0x" + "44cf06eb4783560929b73025762c9e30e8c84a5d67e0a1df581a56adfdaf1a15")
6053885411919235195933892129469424482564n
*/

//44cf06eb4783560929b73025762c9e322e196d76b89801a39847f8202d78d503

console.log(
  arrToScalar([
1148283941303874135n, 10896063542630457777n, 13343018207833685566n, 2772038946681882702n
  ]).toString(16)
);

//2c29f0d64396534a8a05818c3cb1c17f538409cd48a4f33ac81960ca5fd349c93
//22984afcbdda690b1935530f48e87f29d29c29f608aa8aeb60e134f69fae9c2d

//1p: 22984afcbdda690b1935530f48e87f29d29c29f608aa8aeb60e134f69fae9c2d
//6fa9038c992a50698e1bc7c16ae2846a68b12053aae0b9251b313a7e74a00672

export function getQuadness(v: bigint) {
  try {
    Fp.sqrt(v);
    return 0;
  } catch (e) {
    return 1;
  }
}

// commit and was 1
// let y = arrToPoint([
//   0x3c00e55dbafab2n,
//       0x3a70b7ce304a84n, 0x3671905771bbe1n, 0x376a496f69d224n, 0x31e45d1bbb7ebn
// ]);

// genP and was 1
// let y = arrToPoint([
//   0x8d2129f6eaad0n,
//       0xf0d0a7ae2bc4fn, 0x964b7d4d30a55n, 0x1f0f1de2e11f0n, 0xb19b6f00b78n
// ])

// console.log("Quadness:", getQuadness(y));

//last sig newest is 83a012713bf9df0fa92fffc47822c19a2ccd74982d025e1d5a631032b167242b

// let yy = arrToPoint([
// 0x573f5a784671cn, 0x8f28ddff837c8n, 0xda1bb3efc7f52n,
//       0xbbf4dc6b0dec0n, 0xf0661122d999n
// ]);

// Fp.sqrt(yy);

//y: 8f6bdd636464d3785e47db7ad853e95d3286bc00897d2bb434ecbddf426ce1a3

// console.log(x.y)
// console.log(x.toBytes())

//sec0 8769c9a2a381d447bc1e984e79a41e48d84a54597baf8ec53c658b71417c5be1
//sec25 c91667c478adee1d8e3266d84120b9b1ec1d02a41768b08671f10b8799fccf1c
// the last sig is NOT correct. c09b1ddb3f8ff677111a7a9f40bc8795b0f80b9173aaacbdad4d3cefbcaf2ae0, c09b1ddb3f8ff677111a7a9ab0a9986ab0f80b9483bfb342ad4d3cea4cba351f
// Last 21 bytes are incorrect (42 hex chars)
// value comes too latee in prep but my comparisons seem okay for some reason?

//last k: 1124f0d4fa26d647f5dc23d8edc3ca2e07230491b1839546e4447f3 (correct)

// last sig: 8cff3c69342f441a61f3c704fc07dbc46803223d220c1c2c9957476631bb904 (correct)
// s[25][0] = 951365fecebe06e03bf56be5b71cdb120db3e4c88832994c271ced65a614f03e

//genP.x: 3adfe2b247fc222219f7afe9f7e05590e804747a56300f55f91deefd5d15df96 (correct)

//pub[0][0]: 726075aefa8841993fd8029ba60ac8182e3a116e1c52893852d8eb18d0c3f070
//pub[0][1]: 13e6f4469dbdfadd6e1f93a7a7a6f08940e03c7b6885ca1a51b0b171236d38f72
// pub[1][0]: 59246cacfc00731f7b82dd853d303d7b495d3f7987a2dff43ca8b85f3c68c48b
// pub[1][1]: 2cf1643f4f54eef072287955d6d454f8882ec115915c37086451781a24cbdd0bc
// first pubkey of last ring: 7e1acdbf37c0d812c471bd47416beab7d7e5c319eb46d7a5caf5505f4617faf3
// last pubkey of last ring: 1852436799026d1b0b3a1f3868e807b7b698b5e5a1a1c79d9f61046f061a29eaa

//s0 f1c49a6a07dc66693f7a1f488cbdb97e618cfe11bb8cf293af32c17c00f88031
//s1 2663c1587c13a747e38fe1fe02fc7fa0ae9121c5701d004b0a85daf0b12da0cb
//s2 1c3c7bda8326c5a5042ed273f8338f49fab9841b8a852310646568581e259f5e
//s3 91ec45f5ff82fef33add461991c9347c4eae2340a92aa555eb5aeeb15f418d67

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







 13c4dd2c793b827d17d41f37222bf338e513af75e15a129a1e50db5ff4066037
6868db9ea53461117ba985fed7d94699eb3d5e992cf17df34ead8b11bea864f5
dc536ce344c523af67d17f42b443ba636093c51d772257d7418a02730b2a73c5
7de9fb8ecef9f4d88ebd24da9ecf3b18702c8b8ccf2b2870c1314352985d2e3c
c8eb687683b18ea269d154b6c746e20c3da3bf89ccb6c25d415f6448f15d19e0
14f558e8a822ce80870975354275975862b9a4d3bf85480b145796388b97e333
982e27fde2e1927dd8d5fc9581d1a68c913cceb9203bc097b0b1e3ae529d9802


// msg is good

// The problem is that Buffer.from(lastRingNonceCollection[25]).toString('hex') is no good
// should be 031cea616514b354bbe413c7a140a3345cdb8d3b219245bb37bb475d20c18cef
// right now is 0212aafb8940d2815f8e9a3d3603e65d02c3c1f0eb368fcf5c3b64912214d2aa30

//lastRingNonceCollection[24] is good

//The last sig is always off by a few bytes on the bad passes. why?
*/
