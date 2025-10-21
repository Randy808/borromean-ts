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
const BASE_URL = "localhost:30001";

// Create readline interface for user input
// const rl = readline.createInterface({
//   input: process.stdin,
//   output: process.stdout,
// });

// rl.on("SIGINT", () => {
//   console.log("\n\nReceived SIGINT. Exiting...");
//   rl.close();
//   process.exit(0);
// });

// // Promisify readline question
// function question(query: string): Promise<string> {
//   return new Promise((resolve) => {
//     rl.question(query, resolve);
//   });
// }

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
    hash: "a67506b16be49ee025786457e3ec1c9035f9470041d0e288ab426f2b5c236e7a",
    index: 1,
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
  blindingPubkey: Buffer
  // blindingKeyPairs: ECPairInterface[]
): Promise<Psbt> {
  // TODO: Use static blinding key, but generate a blinding keypair dynamically
  // Random asset blinds are used
  await psbt.blindOutputsByIndex(
    Psbt.ECCKeysGenerator(ecc),
    new Map(),
    new Map().set(0, blindingPubkey)
  );

  console.log("✓ Outputs blinded");
  return psbt;
}

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
      blindingData.blindingPubKey
      // blindingKeypairs
    );

    // Step 6: Get custom message from user
    // const message = await question('\nEnter message to embed in range proof: ');

    let recipientBlindingPrivateKey =
      0xfff68d254e89c7aeed25b02778e31778641802d426e256dbd703f2dfd932a45an;

    let userConfidentialAddress = liquidjs.address.toConfidential(
      payment.address!,
      Buffer.from("01fff68d254e89c7aeed25b02778e31778641802d426e256dbd703f2dfd932a45a", "hex")
    );
    console.log("User's conf add", userConfidentialAddress, "\n\n");

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


    console.log("\n=== Transaction Summary ===");
    // console.log(`Transaction ID: ${tx.getId()}`);
    console.log(`Recipient: ${confidentialAddress}`);
    console.log(`Amount: ${amount} sats`);
    // console.log(`Message: "${message}"`);
    console.log("\n✓ Transaction ready to broadcast");

    // console.log(`TX:\n\n\n${t.toHex()}`);

    // let txFinal = liquidjs.Transaction.fromHex("0200000001017a6e235c2b6f42ab88e2d0410047f935901cece357647825e09ee46bb10675a60100000000ffffffff030b0f2e51105fd3b81e262f73cb0ab532cdeb6019dc08f050c316dde1ee88e4803909be6a0528ed411251348e8940648c9a07cf50b2fb7c342ded7af6335aaa84b6070275dff0322450a9478f3bb76c024252c96292a9607c4483a561a5e1a8bc5d31651600142077e1d15a407ae5337520046736227a663403650125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5db88001600142077e1d15a407ae5337520046736227a663403650125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000019000000000000000000247304402203d38a9dcf6b3b88767064e31cb06e3ed960844daae4149886a86c299594d358a02202c5254c726bf05d2640e06727ce568683c72998639a90cd6b6ab9e69ed0f65dc012102f8bd6b4436909c193541b697087f103178522785e2f55b30336bc9d083f62493004301000135b8cd20ab37c3c54dba4686949182a0a516bbe49790f853b67c0cb87a85e6b8d9de0167f048a2e3df8e959792e0e542866a62d38ced06c3236bace78d28da5efd4e10603300000000000000019f60330136ed6ae02da0acdb6d053d48bd82dd9ed6a7a57fdac63ca7e7c4a47e858c068227f7cbce3677dc848cfad697291fed404f61e99d4ae487a2bf5e2c446d45063959067037cc3c98abb90a646652b044df4c7dac8b439b48664658f99155579513df5ddcdf9fea3469b8fee77d3004145045cf1338b259b730548783623fe52c2eadbced655b59667d416e0daaf3fcb1b0ced8bb711695825564d045443c9341e8f6ba59796ae899732bb4a5aa49d3afd48d00d745544d19388e997cd9d7c9fee733b0351f6c7d29a410102dbf98fac2cb916187ab51dd56697fd1721ecba9364a2f313c46148d3d71e4e403d48951b8c912819961f4037711d09511a546027e1cf704e6a3733231d657955f12dd987dbf151c91249248323ae0d5725c9df52497bc875515e6c669077249c3166fcc52bdeb4bce842edf8f49857283f4abd27db758d2654821e30be05cb8de65e1d5cff9b968e8a3ed76908c6da0c31b4aa0147a979abd40bd3ee62c5eb61f79d58b1d22457a72d55f4a085f1fd15854df7c9e417989f80093928b2a1261ca0f0ca7470cb8130a3697739f555ddc093713f4e397264c4118c1b5c40aa68cf923832c1fbd72c89e7b75bb719aa9c8f01fdd24233d0ca4a5f5c39e291923c30f8a51a86a0f38138a8bdfe38309d676a041ca710050b3f0b5cd2f466e4fa36133696c1212b3cb525ef88d4c7e23121ce6cf5d4bdf0319b6d2be15ecdc016f55767c89d844d284ee04fd9148ba86abd4e923ccbca8a476020e7184065778017172b57ce8da32cec67678db593afaeb449cea69e61c03d52fefd1beff9c802d6a5d5338949540ea24b61895cd0297c34a3fb5b8a98b8ad070e826d53921b3a5b86e62fa4f121003cd5081624a66b167419d428ed4865d50b1e1bd70874e6f1cbf47a1710ffbf4151c928434b954297a09e3347bdf695f8e9491186be088d66649c1bc24561fdb48908484abeb898f3bba8b2b8dd3b5324e98d330889f0628dce0c1d7d491228f6065c9b3ac8cbb5e4076f42de16904c77b73a19f81a27fdd98eac766cf0ec92f6803c4cc8bf1f962f20dc50a80b790841da04f164e0f627f9d49954c83f1eb0de00604f56c781236fb6cbbce6bb4b0f659ab2ce30f2f323663bd9e714c744cc3d17adf40743c0a6c45e4e0079306da21b0d7c8da0ac3a41be85da926deb93f6bbf1c4ef4bdafe078853aa9479cbd23fc6cd95684b4627fcf4d02cf328ecd952b7b6e0c448c2c2594060a8b8fb0892c850e1c6e2865d1810cbd1d03fca7544f6b3cc788c936b85669aaec4905bb1b3815da0edea2c2f0f0be02bdafa5f9053ce7d64d5a6b9a472bc2436e88a4573de8cd954ccca0e66b22adb037618c52ffa4b34114bb93a29f09cddc116bba21f73171ca402f8321647279c54e0c46abfc98c5a81c350d260a29aa1c10d6864fce08110a00b57b7fba201fd8e9bc24686741c22866d50fdd0152f1ea42d493c518f98b5ffb678ed3f0be0dc36a426da0d8647d687ae8b60189c153b4bf1bfa6b9f7432c6b96d2c55b696c892d2030b55569b3272d03a69886d28ec17fb2a5f6032d5179a7bbf01e64efcddb4c3ff404f9cf710481ff9dfee4c14e32d4400f5254e2576e042a1af53bad20751433fbcb00e5e18721fc2a327b520693f3e53e6abbb4637d4e1354f9c12974b0e28388ee5c39e9efe8eac1c468d97eee6c223bff871bc0246a37d28e5f6884dfc9d6b6e781b8db1fb2c197022063f442d1b859eb48b2cbe0bfc09a6c57a4279e726b1e1e469e27206d4a6a810d372a93307e3cd730c9b3841227f2861989446758cbaf8e0c3e785b5bfc68ffadf73f9c3f8403215e325136367f503cb2306c58f15747c6e77a4a4866c56363cf05fc11ff09f5da42bbfe1ac8dd562adfd05c03dd0dfb53882b6c89fdacba2e2d550668b9124b86b550a70be7219d1e2e478e92014ba7429713ddcf16880725ae0c0c967ffe8e3f53c834e58da8825f708a8bc6616cb4ccbafed1bbdba373694544d6692ec4138cf608b3967264c61f8ccdded6a766d9f82e707d867766e3900a72bce1356c69dac21208aae70afd77c1b8c4a2d7b5afa8570944062612445893551ed7f47725e2b281eeca85f3b4944f879b75a88fd70e72ab03b20368ae319af8eaf12fa95e457841e6344ba2095469aa7aaa0fa9b3ce055473f968a2580389379ee8bf607227a72a2c0e2822649bcc389c28090e55b0d5983d59a0339bdbc6bcd160beb7cd55bfc7e45508b662c8c4b7292590cb19fd38812b947e19eb298fdd761a08b9a2688c1bec6c26fd0040e0aeb8faa50434213da72ff760bda758ce0f8ebd0f555b88eedebdfb18e5a2d9248aff86bf4578e3c1424ebb2137a928e3ba477fef5e1a09cec596bd6dc495bf6dbf9841f25967578dac3b553e1910188935f0e16ac93f57f2851893ae8c5f93a9e7dcd03806409f493a3ea79ab4546e667226d7b669605b47038ce2ff8f9c707be5a75a031551414ee834d3125da5f445bbd3497dab3de4b5f21ef237eeb786c2ff9853a90ae3d3d46b9dc753c0ee662e1f5a47e1d80661a4a287d1368bcdedfc13dfdb52bd76a1187cb3311a07878d8f47bb9765381743a0e0c397fd0a49121df6c1093ed8efbcc51c827e36a869efa0fb16a7bd08ad5b15d92bf09579f4d148f550f915cc7b46d2ca16399bccd2ab37b27ed2f17f3290141f1cf17114bb3e2d87fe0cc4547d2512c3c2ba54acb3951e4f77e11f380796225d4216ffedff022ad36113f7fbc8048ea6b999ffa7812648ba45d6d808a63516711cd04192c11f28fb0e764b5c293b0e7a578d82c9546686910850588623370b24e13f8d93370ba3ce1d4fbc9817d247b47435ac31aeff1e9b1aa5dc0afacf12cc2a5e65351580a4ff911aa6c29b0e68524a1a5c4d399707ff07b49942b31dedb51a3479f0d7fbc570bc62c442c4ef7167d4c595ca741d69c89eb697b452100d93c691bc73aeee45dc36c12953df11849a541b4278aca67400fbf55bc668cf9862bcc7f7ec782678aeab3e766999cb28cc94492ba74649f252ff8e6bbff2485ca6c63ec274f898b8dab5baf95c5c8fa9a20e1a602eb72af53c881d0c89cdabd569b3d20fa23ab587fdfce79433ab1bc55219d754774ddec37814d5c915071501f3382214049b063a3f21b11647414d168c9a8105c5afe35f92358b1c829c730e9c10544c4d86d95d1d329f27dc6f8a3a294596a267af3d362859d9fb76a37142512fa70715c17139d8548dde7927d8030f070977301fb41b3b86d84d9ab63321074db5a1972e82cf29e934fc20dee32c78ceabce826d2c88764601ec698e3c8ad0ba30eabe150c5fd91a10f4b2d957889bada794bbc94bd098a6d060d9d0d88acb74a2dc12e584715ede945174cacf26289a0101cff89e76384df5309e12ab9368be0e5cebc1ba1191172e2cbc68ed97c5c795fc86d23f8874b921e50c169eb9504ee6b7ad38c80bf88bff7eca8fb25efc250e011b513e606f7589d340db12042ed8df4c78317a183f3f0b9eee711b54a1a71dd190ea0124dc0036713325b0db850b39a30a242acfa0852436e3e07817bfb2703f8a45f59f76824fadf02da9f4653ff00b7fba0bacda67a87191d740ddc3f47867fb27bb305c773cd30271dc3f87270643f378ee3dde7af4ded4f5f727c1dcd12a148a66d06307c0ad1b03942776235aa3d7221a998141906de7f3b7e045913769b03e35c487d11c85a413351edd5881d9b0d90277649e95bd4827db7486451320027648be6492e0659017446af23043f02672754108bc6c46293099979caca569455b5fc0b52a2c3e67e4343c3395702179195e2f5e5d4037de1336adb631d2d7bbb5501f486692163e7021f9ba13b7c253c3b1fc8a10464a6e7081aa110c6f1888ce9d5c90e44a74fa340ad13eb5d0c53ea227f068d0c40b9d07fb71ff5a0e6c662c55645d6e259d5c4d10935bb224af58358676f3e2fe209e173b1a5096bcee82bcdec4c950c1f61a5e1e44b5b449682383432d0edf9d3dac08ebd37a53af908bf6473f0b00ace904505dde5049524f63a039a0d011cd507cdf74b5775f71b0cdd3e79cb4c0319fd160c5e96541a7bfb8b1527cc923e59f18131a9fba550e86081bd2771d778591e1f1c10f91280f9b6c98d39ce9ac284ff1ea4d828212e9b24fca3f9a07394a6b12d4e19d57f93cb0d0b220ba6e4b5b822e8d47210dae93655b7c71c6c660168f11d4258b4390aba27381682539fc8d0e60e529426193b7d5b1364201ec9519205f587c1cc1b472825473774d2778864b55a1c897957873a4ff987e227b94d83630045269938931a504617ae8431a2f3d73fc0ecbb608c81ad0987bb6dce3bfe4b6cdd3800b38e34e684ca170516ba45280a5a205e079955381884da066e465616e2d192beb8fe034a88f18a357472ecc55aebc2b6776ed5270fff02da9517e4cb3699525c60cc1086421b5597a6333a8e93425f67f7ce94786b626a0dc0b62d6f5541b6ddbfadc6cfe383672ce5eccb2c3ffac89933d6313bea3b77082bb9fae4886ca924df0cd7f9dffc1ba95c8ef45f14bbfec1688eed5854931c4d8df1f2f7118742dda58964da944a64c9da28de130efd8a1839cee6792f10ad9a77a4fd9195985cf5ee2c2f4e4e33dd26a9351fa93137e29075971d340b4da75335e291eefcdb446e43150802184dd88fbcd770fa6fdf91e3da8f702eefa21f0d3d4b57074e3ddc160b54550b316c3b463359a513bd9733122e936286c3090b4720bd2ad4a3e7b00afdc57515252feed99728090438a64383b7a58655bda13de6e650773b7e520a567db8aa30a45fa96def7aa281308c3d84a2f45036310d5b05de6083ee66c0a121e63ad96b180331cf4186f846b37688d64358c76a6d480143dd4a76f6b3e7242cdf57690211b881a6afa5241e678073b0d45755eb5940556bac026d1cb06e3846997a8f6ee5ff98a12ede7c6301cefe18f7d247c57b5e7fe677fd1b8a1a964c80aa28a7bf63e53618529b5b9988ff5c8c90b59c7dbd97eede9d1ce55865cc1330faaed9bec3248169e9e7f59f204cdc5fb7273a8c7005469db14728072a3b4173b1719f9e281a6f6b1e5245fc6f15e1e0a91510f0f241aeb041ac2093ebd303f790401fbcb7f8496f1947daea51a6b85a9f8f6a45c26d5f5c9617ce1865d6ef9fde28462e2370f0ea75748d4ee3ed383c7f6305a54fbcca5ad256cc3e5a76caea0ff4333e13120281f3814307125703e09df37d69f6899479a2c55276a6219b94cd19ea55fdfc4c6b604043440f084c348c58e8f60c913ef9588577c6a4f25f5c25ae8710114342b66bc3868ece8d9549667797f3b142edad124a96c1d91780aa81cb51d12f18839dfa7b6efd590e3e8825654d9952238e77464ce817192f8da9784e3ef8779ea0550f604ab5acbf7118f475b3f99f3c8086ba96539c21f16ec18925e635146377818fdbbb13404dd26377c92ad94591c1872c0c6fd5444c6a6d10f741670ac3c0167579dd19f14c45120e3882c36455247c7cc47e94d1257c1d494b1c422be58028b63caae4a0fd9c7b7b324a03c26f290e33618b1425f995621d1d31f8c663e95efa17a9677d61e0bea224152e5af4ab1f6e6a821aaf8594b781d0bbc7743e5d5a9267f23b045b2aec2da7e22c93f9d80f8597e8856556ac46f099e2fd4a658c30e177df28cf6645d9bd66bd06ee24b19fc16d3ca7bb712ff165c3d635b06385bef6f8614a2b9e994aa6ea31c2c235a8ee22a30f4fe2b910991ee207f6c46ae46c1b5f179d39b63e35907d9ba3cad0460fa1f42b2adb81b6383e9ad1d74ad7bafcedf075d64926b6cf418e501f91a591eeb13539da729e823b148f00000000")
    // console.log()

    await showMessages(recipientBlindingPrivateKey, OUTPUT_INDEX);

    // To broadcast: use Liquid node RPC or API
    // const txHex = tx.toHex();
    // console.log(`\nTransaction hex: ${txHex}`);
  } catch (error) {
    console.error("Error creating transaction:", error);
  }

})();

async function showMessages(
  recipientBlindingPrivateKey: bigint,
  outputIndex: number
) {
  let addressTxsResponse = await fetch(
    `http://${BASE_URL}/address/ert1qlg6t57zndrregrgnyzp6l9mk8858jgk0m04h4g/txs`
  );

  let addressTxs = await addressTxsResponse.json();

  for (let tx of addressTxs as any) {
    //99998600
    for (let out of tx.vout) {
      if (out.value === 99998600) {
        await showTxMessage(tx.txid, recipientBlindingPrivateKey, outputIndex);
        break;
      }
    }
  }
}

async function showTxMessage(
  txid: string,
  recipientBlindingPrivateKey: bigint,
  outputIndex: number
) {
  let txHexResponse = await fetch(`http://${BASE_URL}/tx/${txid}/hex`);
  let txHex = await txHexResponse.text();
  let txFinal = liquidjs.Transaction.fromHex(txHex);

  let nonceCommitment2 = txFinal.outs[outputIndex].nonce.toString("hex");
  if (nonceCommitment2.length < 32) {
    return;
  }
  let verificationNonce2 = getNonce(
    nonceCommitment2,
    recipientBlindingPrivateKey
  );

  let decrypted = getDecryptedRingSignatureRangeProof(
    verificationNonce2,
    txFinal,
    outputIndex
  );
  let message = decrypted.subarray(64, 64 + 32);
  console.log("\n\nMESSAGE:\n\n", message.toString("ascii"));
}

//Reference txid: 565e5ed7937871a52fab695ccb51f2aa17fd1039bab471a5d136d3be53e728e5

/*
To test:
- Call e sendtoaddress <address printed above>
- Get txid and identify our output
- Adapt the tx in addInput call to use correct txid and index
- Run messaging-prototype.ts
- Get the tx hex and broadcast it

*/
