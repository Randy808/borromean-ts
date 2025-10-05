const assetId = "25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a";
const assetBlinder = "f7c6bbdbd2c5041e210f69e1fe2bfa27928eb87e198bc137495becca70a93182";

//6480 0s, so 3240 bytes
let zeros = new Array(3240).fill(0).reduce((acc: Buffer, n) => {
  return Buffer.from([...acc, n]);
}, Buffer.from([]));


// 3 of these is 32 bytes since value is represented with 8 bytes
let valueHex = "0000000005f5e0ff";
let hex = assetId + assetBlinder + zeros.toString("hex") + valueHex + valueHex + valueHex;


//3328 in size
export default Uint8Array.from(Buffer.from(hex, 'hex'))