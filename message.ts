import { getSecIdx } from "./utils";

function stringToHex(str: string) {
  let hexBytes: string[] = [];
  for (let i = 0; i < str.length; i++) {
    // Get the character code (ASCII/Unicode value)
    let charCode = str.charCodeAt(i);
    // Convert to hexadecimal and pad with a leading '0' if necessary
    let hex = charCode.toString(16).padStart(2, "0");
    hexBytes.push(hex);
  }
  return hexBytes.join(""); // Join the hex values to form a single hex string
}

function getMessage(
  numRings: number,
  ringSize: number,
  assetId: string,
  assetBlinder: string,
  valueHex: string,
  lastSignerIndexIsAtEndOfRing: boolean = false,
  message: string = ""
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

  let embeddedMessage = stringToHex(message);

  // will equal 3240 unless signer index for last ring is defined as last
  // this is impossible when sending smaller amounts.
  let numberOfZeros =
    bufferIndexOfWhereToWriteValue -
    sizeOfAssetInfo -
    embeddedMessage.length / 2;

  let zeros = new Array(numberOfZeros).fill(0).reduce((acc: Buffer, n) => {
    return Buffer.from([...acc, n]);
  }, Buffer.from([]));

  /*
    for ring in num rings
      for sig in ring
        if(secidx === sig)
          continue

        sig = writeMessageFromCursor()

        padSigIfMessageIsShort

        addToCummulativeHexString

  */

  let secidx = getSecIdx(BigInt("0x" + valueHex));
  let fakeSignatures = "";
  let hexMessageToBeWritten = embeddedMessage.slice();

  for (let ringIndex = 0; ringIndex < numRings; ringIndex++) {
    for (let sigIndex = 0; sigIndex < ringSize; sigIndex++) {
      if (ringIndex === 0 && sigIndex === 0) {
        fakeSignatures += assetId;
        continue;
      }

      if (ringIndex === 0 && sigIndex === 1) {
        fakeSignatures += assetBlinder;
        continue;
      }

      if (secidx[ringIndex] === sigIndex) {
        fakeSignatures += Buffer.from(new Array(32).fill(0)).toString("hex");
        continue;
      }

      if (ringIndex === numRings - 1) {
        if (secidx[ringIndex] === ringSize - 1) {
          if (sigIndex === ringSize - 2) {
            fakeSignatures +=
              "0000000000000000" + valueHex + valueHex + valueHex;
            continue;
          }
        } else if (sigIndex === ringSize - 1) {
          fakeSignatures += "0000000000000000" + valueHex + valueHex + valueHex;
          continue;
        }
      }

      let fakeSig = hexMessageToBeWritten.substring(0, 64);
      fakeSig = fakeSig.padEnd(64, "00");
      fakeSignatures += fakeSig;
      hexMessageToBeWritten = hexMessageToBeWritten.substring(64);
    }
  }

  // 3 of these is 32 bytes since value is represented with 8 bytes
  // let valueHex = "0000000005f5e0ff";
  let hex = fakeSignatures;

  console.log("ASSERT", hex === fakeSignatures);

  let fakeSignatures2 =
    embeddedMessage +
    zeros.toString("hex") + // 3240
    valueHex +
    valueHex +
    valueHex;

  let messageBytes = Uint8Array.from(Buffer.from(hex, "hex")); // 3317? should be 3328

  //3296 (((rings - 1) * 4 + 3) * 32) should have the value 128
  messageBytes[lastRingPositionInSignatureBuffer] = 128;

  return messageBytes;
}

//3328 in size
export default getMessage;
