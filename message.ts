function stringToHex(str: string) {
  let hexBytes: string[] = [];
  for (let i = 0; i < str.length; i++) {
    // Get the character code (ASCII/Unicode value)
    let charCode = str.charCodeAt(i);
    // Convert to hexadecimal and pad with a leading '0' if necessary
    let hex = charCode.toString(16).padStart(2, '0');
    hexBytes.push(hex);
  }
  return hexBytes.join(''); // Join the hex values to form a single hex string
}

function getMessage(
  numRings: number,
  ringSize: number,
  assetId: string,
  assetBlinder: string,
  valueHex: string,
  lastSignerIndexIsAtEndOfRing: boolean = false
) {
  // const assetId =
  //   "25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a";
  // reversed is 5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225
  // const assetBlinder =
  //   "f0b8dd8fa6cd62ed82ad112827eee152cba36a960c22fa981c0214806b0d7ea8";

  let lastRingIndex = numRings - 1;
  let lastIndexOfRing = ringSize - 1;
  let sizeOfSignature = 32;

  if (lastSignerIndexIsAtEndOfRing) {
    lastIndexOfRing -= 1;
  }

  let lastRingPosition = lastRingIndex * ringSize;
  let lastRingPositionInSignatureBuffer =
    (lastRingPosition + lastIndexOfRing) * sizeOfSignature;

  let sizeOfAssetInfo = assetId.length / 2 + assetBlinder.length / 2;

  let bufferIndexOfWhereToWriteValue = lastRingPositionInSignatureBuffer + 8;

  let embeddedMessage = stringToHex("hello world");

  // will equal 3240 unless signer index for last ring is defined as last
  // this is impossible when sending smaller amounts.
  let numberOfZeros = bufferIndexOfWhereToWriteValue - sizeOfAssetInfo - embeddedMessage.length/2; 

  

  let zeros = new Array(numberOfZeros).fill(0).reduce((acc: Buffer, n) => {
    return Buffer.from([...acc, n]);
  }, Buffer.from([]));

  // 3 of these is 32 bytes since value is represented with 8 bytes
  // let valueHex = "0000000005f5e0ff";
  let hex =
    assetId + // 32
    assetBlinder + // 32
    embeddedMessage +
    zeros.toString("hex") + // 3240
    valueHex +
    valueHex +
    valueHex;

  let messageBytes = Uint8Array.from(Buffer.from(hex, "hex"));// 3317? should be 3328

  //3296 (((rings - 1) * 4 + 3) * 32) should have the value 128
  messageBytes[lastRingPositionInSignatureBuffer] = 128;

  return messageBytes;
}

//3328 in size
export default getMessage;
