const assetId = "25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a";
const assetBlinder = "f0b8dd8fa6cd62ed82ad112827eee152cba36a960c22fa981c0214806b0d7ea8";

//6480 0s, so 3240 bytes
let zeros = new Array(3240).fill(0).reduce((acc: Buffer, n) => {
  return Buffer.from([...acc, n]);
}, Buffer.from([]));


// 3 of these is 32 bytes since value is represented with 8 bytes
let valueHex = "0000000005f5e0ff";
let hex = assetId + assetBlinder + zeros.toString("hex") + valueHex + valueHex + valueHex;


let messageBytes = Uint8Array.from(Buffer.from(hex, 'hex'));

//3296 (((rings - 1) * 4 + 3) * 32) should have the value 128
messageBytes[3296] = 128;

//3328 in size
export default messageBytes;