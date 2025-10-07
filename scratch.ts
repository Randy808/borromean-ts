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
  const p: bigint = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

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
    4866259226170064n, 2378175099659704n, 5908122959302592n, 
      6550776891409480n, 264261619153502n
  ],
  [
    18917814979659974n, 
      19442678258738232n, 17650498300672612n, 17661547974393009n, 
      1202890606620668n
  ],
  [
1597975539001942n, 597842873670386n, 
      2820681357962310n, 1410769394091263n, 256511569101294n
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
3265982544138575n, 
      1390286232566149n, 3140963245541895n, 3471786715142565n, 94125363524639n
]).toString(16))

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
