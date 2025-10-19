// Try to read keypair from file

// Generate keypair if there was an exception and keypair couldn't be read
// Save private key to file in this case

// take in confidential address from user

// Craft tx to send 1000 sats to confidential address

// Get blech32 data from address so we can blind outputs

// then blind the outputs

// Take in a message from user

// modify range proof to contain msg (new library call to 'modifyRangeProof' should just take in tx)

import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";
import { ECPairFactory, ECPairInterface } from "ecpair";
import * as ecc from "tiny-secp256k1";
import * as liquidjs from "liquidjs-lib";
import { Psbt } from "liquidjs-lib/src/psbt";
import { address, payments, networks } from "liquidjs-lib";
import {
  getDecryptedRingSignatureRangeProof,
  getNonce,
  modifyRangeProof,
} from "./modify-tx-with-rangeproof";

// Initialize ECPair with tiny-secp256k1
const ECPair = ECPairFactory(ecc);

// Liquid network configuration
const LIQUID_NETWORK = networks.regtest;
const KEYPAIR_FILE = "liquid_keypair.txt";

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.on("SIGINT", () => {
  console.log("\n\nReceived SIGINT. Exiting...");
  rl.close();
  process.exit(0);
});

// Promisify readline question
function question(query: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(query, resolve);
  });
}

/**
 * Try to read keypair from file
 */
function readKeypairFromFile(): ECPairInterface | null {
  try {
    const privateKeyHex = fs.readFileSync(KEYPAIR_FILE, "utf-8").trim();
    const keyPair = ECPair.fromPrivateKey(Buffer.from(privateKeyHex, "hex"), {
      network: LIQUID_NETWORK,
    });
    console.log("✓ Keypair loaded from file");
    return keyPair;
  } catch (error) {
    console.log("✗ Could not read keypair from file");
    return null;
  }
}

/**
 * Generate new keypair and save to file
 */
function generateAndSaveKeypair(): ECPairInterface {
  console.log("Generating new keypair...");
  const keyPair = ECPair.makeRandom();

  // Save private key to file
  const privateKeyHex = keyPair.privateKey!.toString("hex");
  fs.writeFileSync(KEYPAIR_FILE, privateKeyHex, "utf-8");
  console.log(`✓ Private key saved to ${KEYPAIR_FILE}`);

  return keyPair;
}

/**
 * Get blinding key from confidential address
 */
function getBlindingDataFromAddress(confidentialAddr: string): {
  blindingPubKey: Buffer;
  unconfidentialAddress: string;
} {
  // Decode the confidential address to extract blinding public key
  const decoded = address.fromBlech32(confidentialAddr);

  return {
    blindingPubKey: decoded.pubkey,
    unconfidentialAddress: address.toBech32(
      decoded.data!.subarray(2),
      decoded.version,
      LIQUID_NETWORK.bech32
    ),
  };
}

let assetBuffer = Buffer.concat([
  Buffer.from([0]),
  Buffer.from(LIQUID_NETWORK.assetHash, "hex").reverse(),
]);

/**
 * Create and blind a transaction
 */
function createBlindedTransaction(
  keyPair: ECPairInterface,
  blindingData: any,
  amount: number
): Psbt {
  const psbt = new Psbt({
    network: LIQUID_NETWORK,
  });

  const ONE_BTC = 100_000_000;

  const payment = payments.p2wpkh({
    pubkey: keyPair.publicKey,
    network: LIQUID_NETWORK,
  });

  psbt.addInput({
    hash: "61160cca8baf0ccfbfbc043fa829e0f69b04a6069aa7ce3483095e3264a9d986",
    index: 0,
    witnessUtxo: {
      asset: assetBuffer,
      script: payment.output!,
      value: liquidjs.confidential.satoshiToConfidentialValue(ONE_BTC),
      nonce: Buffer.alloc(1, 0),
    },
  });

  // In a real application, you would:
  // 1. Fetch UTXOs for the sender address
  // 2. Add inputs to the PSBT
  // 3. Calculate fees
  // Here's a skeleton structure:

  // Example: Add input (you'd need real UTXO data)
  // psbt.addInput({
  //   hash: 'previous_tx_id',
  //   index: 0,
  //   witnessUtxo: {
  //     script: Buffer.from('script_hex', 'hex'),
  //     value: confidential.satoshiToConfidentialValue(inputAmount),
  //     asset: confidential.assetToConfidentialAsset(assetId),
  //     nonce: Buffer.alloc(1, 0)
  //   }
  // });

  // Get blinding data from confidential address

  // Add output for recipient
  psbt.addOutput({
    script: address.toOutputScript(
      blindingData.unconfidentialAddress,
      LIQUID_NETWORK
    ),
    value: liquidjs.confidential.satoshiToConfidentialValue(amount),
    asset: Buffer.from(LIQUID_NETWORK.assetHash + "01", "hex").reverse(), // L-BTC asset
    nonce: Buffer.alloc(1, 0),
  });

  const FEE = 400;

  psbt.addOutput({
    script: address.toOutputScript(
      blindingData.unconfidentialAddress,
      LIQUID_NETWORK
    ),
    value: liquidjs.confidential.satoshiToConfidentialValue(
      ONE_BTC - amount - FEE
    ),
    asset: Buffer.from(LIQUID_NETWORK.assetHash + "01", "hex").reverse(), // L-BTC asset
    nonce: Buffer.alloc(1, 0),
  });

  psbt.addOutput({
    script: Buffer.alloc(0),
    value: liquidjs.confidential.satoshiToConfidentialValue(FEE),
    asset: Buffer.from(LIQUID_NETWORK.assetHash + "01", "hex").reverse(), // L-BTC asset
    nonce: Buffer.alloc(1, 0),
  });

  // Add change output (if needed)
  // psbt.addOutput({ ... });

  // Sign inputs
  // psbt.signInput(0, keyPair);
  // psbt.finalizeAllInputs();

  console.log("✓ Transaction created");
  return psbt;
}

/**
 * Blind transaction outputs
 */
async function blindOutputs(
  psbt: Psbt,
  blindingPubkey: Buffer,
  // blindingKeyPairs: ECPairInterface[]
): Promise<Psbt> {
  // const blindingPrivkeys = [
  //     Buffer.from(
  //       '13d4dbfdb5074705e6b9758d1542d7dd8c03055086c0da421620eaa04717a9f7',
  //       'hex',
  //     ),
  //   ];
  //   const blindingPubkeys = [
  //     blindingPubkey
  //   ]

  // Blind the outputs using the blinding arguments

  // const keyPair = blindingKeyPairs[0];

  let recipientBlindingPrivateKey = Buffer.from(
    "fff68d254e89c7aeed25b02778e31778641802d426e256dbd703f2dfd932a45a",
    "hex"
  );

  // TODO: Use keypair instead of blindingPubkey
  const blinded = await psbt.blindOutputsByIndex(
    Psbt.ECCKeysGenerator(ecc),
    // (o: any) => {
    //   return {
    //     privateKey: keyPair.privateKey!,
    //     publicKey: keyPair.publicKey!,
    //   };
    // },
    new Map(),
    new Map().set(0, blindingPubkey)
  );

  console.log("✓ Outputs blinded");
  return psbt;
}

/**
 * Modify range proof to contain custom message
 */
// function modifyRangeProof(
//   tx: liquidjs.Transaction,
//   message: string
// ): liquidjs.Transaction {
//   // This is a placeholder for the range proof modification
//   // In practice, you would use a library function that allows
//   // embedding data in the range proof

//   console.log(`✓ Range proof modified with message: "${message}"`);

//   // The actual implementation would involve:
//   // 1. Extracting the range proof from the confidential output
//   // 2. Re-generating the range proof with the custom message
//   // 3. Replacing the range proof in the transaction

//   // For now, this is a conceptual placeholder
//   // tx.outs.forEach((output, index) => {
//   //   if (output.rangeProof && output.rangeProof.length > 0) {
//   //     // Modify range proof to include message
//   //     const modifiedProof = customRangeProofFunction(output, message);
//   //     tx.outs[index].rangeProof = modifiedProof;
//   //   }
//   // });

//   return tx;
// }

/**
 * Main application
 */
void (async function main() {
  console.log("=== Liquid Sidechain Transaction Application ===\n");

  // Step 1: Load or generate keypair
  let keyPair = readKeypairFromFile();
  if (!keyPair) {
    keyPair = generateAndSaveKeypair();
  }

  // Get user's own address for reference
  const payment = payments.p2wpkh({
    pubkey: keyPair.publicKey,
    network: LIQUID_NETWORK,
  });
  console.log(`Your address: ${payment.address}\n`);

  // Step 2: Get confidential address from user
  const confidentialAddress =
    "el1qqfj44uf6v0wffqm5lnapr9rq4j49uzd7fq50djvn25v3ndlj5u8gcgrhu8g45sr6u5eh2gqyvumzy7nxxspk29mdf38fl94st"; //await question('Enter confidential address to send to: ');

  if (!confidentialAddress || confidentialAddress.length === 0) {
    console.log("No address provided, exiting...");
    rl.close();
    return;
  }

  // Step 3: Create transaction
  console.log("\nCreating transaction to send 1000 sats...");
  const amount = 1000; // sats

  try {
    // // Step 4: Get blinding data from address
    const blindingData = getBlindingDataFromAddress(confidentialAddress);
    console.log("✓ Blinding data extracted from address");
    console.log("Blinding data", blindingData.blindingPubKey.toString("hex"));

    // Step 5: Create and blind transaction
    let psbt = createBlindedTransaction(keyPair, blindingData, amount);

    let blindingKeypairs = [ECPair.makeRandom()];
    console.log(
      `Blinding keypair is ${blindingKeypairs[0].privateKey?.toString(
        "hex"
      )}\n\n`
    );
    psbt = await blindOutputs(
      psbt,
      blindingData.blindingPubKey,
      // blindingKeypairs
    );

    // Step 6: Get custom message from user
    // const message = await question('\nEnter message to embed in range proof: ');

    let recipientBlindingPrivateKey =
      0xfff68d254e89c7aeed25b02778e31778641802d426e256dbd703f2dfd932a45an;

    // let nonce = getNonce(
    //   blindingData.blindingPubKey.toString("hex"),
    //   BigInt("0x" + blindingKeypairs[0].privateKey?.toString("hex"))
    // );

    // //565e5ed7937871a52fab695ccb51f2aa17fd1039bab471a5d136d3be53e728e5

    const OUTPUT_INDEX = 0;

    // // Step 7: Modify range proof to contain message
    let t = psbt
      .clone()
      .signInput(0, keyPair)
      .finalizeAllInputs()
      .extractTransaction();

   

     let nonceCommitment = t.outs[OUTPUT_INDEX].nonce.toString("hex");
    let verificationNonce = getNonce(
      nonceCommitment,
      recipientBlindingPrivateKey
    );
    
    t = modifyRangeProof(verificationNonce, t, OUTPUT_INDEX);

    // let t2 = liquidjs.Transaction.fromHex(t.toHex())
    
    // console.log("\n\nT2 START\n\n\n")
    // modifyRangeProof(verificationNonce, t2, OUTPUT_INDEX);
    // console.log("\n\n\nT2 END\n\n")

    // psbt.signInput(0, keyPair);
    // psbt.validateSignaturesOfInput(0, Psbt.ECDSASigValidator(ecc));

    //THIS DOESNT WORK. txOutputs IS OVERRIDDEN. USE TXHEX2.
    // psbt.txOutputs[OUTPUT_INDEX].rangeProof = t.outs[OUTPUT_INDEX].rangeProof;
    // psbt.finalizeAllInputs();

    console.log("\n=== Transaction Summary ===");
    // console.log(`Transaction ID: ${tx.getId()}`);
    console.log(`Recipient: ${confidentialAddress}`);
    console.log(`Amount: ${amount} sats`);
    // console.log(`Message: "${message}"`);
    console.log("\n✓ Transaction ready to broadcast");

    console.log(`TX:\n\n\n${t.toHex()}`);

    let txHexResponse = await fetch(
      "http://localhost:30001/tx/195e705e80beeb724308fe4fbbf5ef3ce1aed02af65ad81dfbadc82290273567/hex"
    );
    let txHex = await txHexResponse.text();
    let txFinal = liquidjs.Transaction.fromHex(txHex);

    let nonceCommitment2 = txFinal.outs[OUTPUT_INDEX].nonce.toString("hex");
    let verificationNonce2 = getNonce(
      nonceCommitment2,
      recipientBlindingPrivateKey
    );

    let decrypted = getDecryptedRingSignatureRangeProof(
      verificationNonce2,
      txFinal,
      OUTPUT_INDEX
    );
    let message = decrypted.subarray(64, 64 + 32);
    console.log("\n\nMESSAGE:\n\n", message.toString("ascii"));

    // To broadcast: use Liquid node RPC or API
    // const txHex = tx.toHex();
    // console.log(`\nTransaction hex: ${txHex}`);
  } catch (error) {
    console.error("Error creating transaction:", error);
  }

  rl.close();
})();

//Reference txid: 565e5ed7937871a52fab695ccb51f2aa17fd1039bab471a5d136d3be53e728e5

/*
To test:
- Call e sendtoaddress <address printed above>
- Get txid and identify our output
- Adapt the tx in addInput call to use correct txid and index
- Run messaging-prototype.ts
- Get the tx hex and broadcast it

*/
