import { Transaction, Input, Output } from "../transaction";
import { reversify, sha256 } from "../../utils";
import { compactSize } from "./compactSize";
import { getNextNBytes } from "../script/utils";

export class Serializer {
  static serializeTx(tx: Transaction) {
    let serializedTx = "";

    const version = Buffer.alloc(4);
    version.writeInt16LE(tx.version, 0);
    serializedTx += version.toString("hex");

    const numInputs = compactSize(BigInt(tx.vin.length));
    serializedTx += numInputs.toString("hex");

    for (let i = 0; i < tx.vin.length; i++) {
      serializedTx += Serializer.serializeInput(tx.vin[i]);
    }

    const numOutputs = compactSize(BigInt(tx.vout.length));
    serializedTx += numOutputs.toString("hex");
    for (let i = 0; i < tx.vout.length; i++) {
      serializedTx += Serializer.serializeOutput(tx.vout[i]);
    }

    const locktime = Buffer.alloc(4);
    locktime.writeUint32LE(tx.locktime, 0);
    serializedTx += locktime.toString("hex");

    return serializedTx;
  }

  static serializeWTx(tx: Transaction) {
    let serializedWTx = "";

    const version = Buffer.alloc(4);
    version.writeInt16LE(tx.version, 0);
    serializedWTx += version.toString("hex");

    serializedWTx += "0001";

    const numInputs = compactSize(BigInt(tx.vin.length));
    serializedWTx += numInputs.toString("hex");

    for (let i = 0; i < tx.vin.length; i++) {
      serializedWTx += Serializer.serializeInput(tx.vin[i]);
    }

    const numOutputs = compactSize(BigInt(tx.vout.length));
    serializedWTx += numOutputs.toString("hex");

    for (let i = 0; i < tx.vout.length; i++) {
      serializedWTx += Serializer.serializeOutput(tx.vout[i]);
    }

    for (let i = 0; i < tx.vin.length; i++) {
      const input = tx.vin[i];
      if (
        !input.witness ||
        (input && input.witness !== undefined && input.witness.length === 0)
      ) {
        serializedWTx += compactSize(BigInt(0)).toString("hex");
      } else {
        serializedWTx += compactSize(BigInt(input.witness.length)).toString(
          "hex"
        );
        for (const witness of input.witness) {
          serializedWTx += compactSize(BigInt(witness.length / 2)).toString(
            "hex"
          );
          serializedWTx += witness;
        }
      }
    }

    const locktime = Buffer.alloc(4);
    locktime.writeUint32LE(tx.locktime, 0);
    serializedWTx += locktime.toString("hex");

    return serializedWTx;
  }

  static serializeInput(input: Input) {
    let serializedInput = "";

    const txHash = reversify(input.txid);
    serializedInput += txHash;

    const outputIndex = Buffer.alloc(4);
    outputIndex.writeUint32LE(input.vout, 0);
    serializedInput += outputIndex.toString("hex");

    const scriptSig = input.scriptsig;
    const scriptSigSize = compactSize(BigInt(scriptSig.length / 2));
    const sequence = Buffer.alloc(4);
    sequence.writeUint32LE(input.sequence, 0);

    serializedInput += scriptSigSize.toString("hex");
    serializedInput += scriptSig;
    serializedInput += sequence.toString("hex");

    return serializedInput;
  }

  static serializeOutput(output: Output) {
    let serializedOutput = "";
    const amount = Buffer.alloc(8);
    amount.writeBigInt64LE(BigInt(output.value), 0);

    serializedOutput += amount.toString("hex");
    serializedOutput += compactSize(
      BigInt(output.scriptpubkey.length / 2)
    ).toString("hex");
    serializedOutput += output.scriptpubkey;

    return serializedOutput;
  }
}

const weight = (val: Buffer | string, multiplier: number) => {
  return val instanceof Buffer
    ? (val.toString("hex").length / 2) * multiplier
    : (val.length / 2) * multiplier;
};

// export const outputSerializer = (outTx: Output) => {
//   const amount = Buffer.alloc(8);
//   amount.writeBigInt64LE(BigInt(outTx.value), 0);
//   return `${amount.toString("hex")}${compactSize(
//     BigInt(outTx.scriptpubkey.length / 2)
//   ).toString("hex")}${outTx.scriptpubkey}`;
// };

// export const inputSerializer = (inTx: Input) => {
//   let serializedInput = "";

//   const txHash = reversify(inTx.txid);
//   serializedInput += txHash;

//   const outputIndex = Buffer.alloc(4);
//   outputIndex.writeUint32LE(inTx.vout, 0);
//   serializedInput += outputIndex.toString("hex");

//   const scriptSig = inTx.scriptsig;
//   const scriptSigSize = compactSize(BigInt(scriptSig.length / 2));
//   const sequence = Buffer.alloc(4);
//   sequence.writeUint32LE(inTx.sequence, 0);

//   serializedInput += scriptSigSize.toString("hex");
//   serializedInput += scriptSig;
//   serializedInput += sequence.toString("hex");

//   return serializedInput;
// };

// export const txSerializer = (tx: Transaction) => {
//   let serializedTx = "";
//   let serializedWTx = "";
//   let totalWeight = 0;

//   const version = Buffer.alloc(4);
//   version.writeInt16LE(tx.version, 0);
//   serializedTx += version.toString("hex");
//   serializedWTx += version.toString("hex");
//   totalWeight += weight(version, 4);

//   serializedWTx += "0001";
//   let witnessWeights = 2;

//   const numInputs = compactSize(BigInt(tx.vin.length));
//   serializedTx += numInputs.toString("hex");
//   serializedWTx += numInputs.toString("hex");
//   totalWeight += weight(numInputs, 4);

//   for (let i = 0; i < tx.vin.length; i++) {
//     serializedTx += inputSerializer(tx.vin[i]);
//     serializedWTx += inputSerializer(tx.vin[i]);
//     totalWeight += weight(inputSerializer(tx.vin[i]), 4);
//   }

//   const numOutputs = compactSize(BigInt(tx.vout.length));
//   serializedTx += numOutputs.toString("hex");
//   serializedWTx += numOutputs.toString("hex");
//   totalWeight += weight(numOutputs, 4);
//   for (let i = 0; i < tx.vout.length; i++) {
//     serializedTx += outputSerializer(tx.vout[i]);
//     serializedWTx += outputSerializer(tx.vout[i]);
//     totalWeight += weight(outputSerializer(tx.vout[i]), 4);
//   }

//   let isWitness = false;
//   for (let i = 0; i < tx.vin.length; i++) {
//     if (!tx.vin[i].witness || tx.vin[i].witness.length === 0) {
//       serializedWTx += compactSize(BigInt(0)).toString("hex");
//       witnessWeights += weight(compactSize(BigInt(0)), 1);
//     } else {
//       isWitness = true;
//       serializedWTx += compactSize(BigInt(tx.vin[i].witness.length)).toString(
//         "hex"
//       );
//       witnessWeights += weight(
//         compactSize(BigInt(tx.vin[i].witness.length)),
//         1
//       );
//       for (const witness of tx.vin[i].witness) {
//         serializedWTx += compactSize(BigInt(witness.length / 2)).toString(
//           "hex"
//         );
//         witnessWeights += weight(compactSize(BigInt(witness.length / 2)), 1);
//         serializedWTx += witness;
//         witnessWeights += weight(witness, 1);
//       }
//     }
//   }

//   const locktime = Buffer.alloc(4);
//   locktime.writeUint32LE(tx.locktime, 0);
//   serializedTx += locktime.toString("hex");
//   serializedWTx += locktime.toString("hex");
//   totalWeight += weight(locktime, 4);

//   if (isWitness) totalWeight += witnessWeights; //for marker and flag

//   return {
//     serializedTx,
//     serializedWTx: isWitness ? serializedWTx : serializedTx,
//     weight: totalWeight,
//   };
// };

// export const txWeight = (tx: Transaction) => {
//   // return txSerializer(tx).serializedWTx.length / 2;
//   return txSerializer(tx).weight;
// };

// export const txForSigning = (
//   tx: Transaction,
//   input: number,
//   sighash: SigHash
// ) => {
//   const txCopy = cloneDeep(tx);
//   let hashcode = Buffer.alloc(4);
//   switch (sighash) {
//     case SigHash.ALL:
//       for (let i = 0; i < txCopy.vin.length; i++) {
//         hashcode.writeUint32LE(1, 0);
//         if (i === input) {
//           txCopy.vin[i].scriptsig = txCopy.vin[i].prevout.scriptpubkey;
//         } else {
//           txCopy.vin[i].scriptsig = "";
//         }
//       }
//       break;
//     case SigHash.ALL_ANYONECANPAY:
//       hashcode.writeUint32LE(0x81, 0);
//       txCopy.vin = [txCopy.vin[input]];
//       txCopy.vin[0].scriptsig = txCopy.vin[0].prevout.scriptpubkey;
//       break;
//   }

//   return txSerializer(txCopy).serializedTx + hashcode.toString("hex");
// };

export const extractRSFromSignature = (derEncodedSignature: string) => {
  let derEncodingScheme,
    signatureLength,
    r,
    s,
    rLength,
    sLength,
    rest,
    prefix,
    rPadding = "",
    sPadding = "";
  [derEncodingScheme, rest] = getNextNBytes(derEncodedSignature, 1);
  if (derEncodingScheme !== "30")
    throw new Error("Invalid DER encoding scheme");
  [signatureLength, rest] = getNextNBytes(rest, 1);
  [prefix, rest] = getNextNBytes(rest, 1);
  [rLength, rest] = getNextNBytes(rest, 1);
  [r, rest] = getNextNBytes(rest, parseInt(rLength, 16));
  if (r.length === 66) [rPadding, r] = getNextNBytes(r, 1); //account for 00 padding

  [prefix, rest] = getNextNBytes(rest, 1);
  [sLength, rest] = getNextNBytes(rest, 1);
  [s, rest] = getNextNBytes(rest, parseInt(sLength, 16));
  if (s.length === 66) [sPadding, s] = getNextNBytes(s, 1); //account for 00 padding

  return r.padStart(64, "0") + s.padStart(64, "0");
};

const tx = {
  version: 1,
  locktime: 0,
  vin: [
    {
      txid: "3b7dc918e5671037effad7848727da3d3bf302b05f5ded9bec89449460473bbb",
      vout: 16,
      prevout: {
        scriptpubkey: "0014f8d9f2203c6f0773983392a487d45c0c818f9573",
        scriptpubkey_asm:
          "OP_0 OP_PUSHBYTES_20 f8d9f2203c6f0773983392a487d45c0c818f9573",
        scriptpubkey_type: "v0_p2wpkh",
        scriptpubkey_address: "bc1qlrvlygpudurh8xpnj2jg04zupjqcl9tnk5np40",
        value: 37079526,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "30440220780ad409b4d13eb1882aaf2e7a53a206734aa302279d6859e254a7f0a7633556022011fd0cbdf5d4374513ef60f850b7059c6a093ab9e46beb002505b7cba0623cf301",
        "022bf8c45da789f695d59f93983c813ec205203056e19ec5d3fbefa809af67e2ec",
      ],
      is_coinbase: false,
      sequence: 4294967295,
    },
  ],
  vout: [
    {
      scriptpubkey: "76a9146085312a9c500ff9cc35b571b0a1e5efb7fb9f1688ac",
      scriptpubkey_asm:
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 6085312a9c500ff9cc35b571b0a1e5efb7fb9f16 OP_EQUALVERIFY OP_CHECKSIG",
      scriptpubkey_type: "p2pkh",
      scriptpubkey_address: "19oMRmCWMYuhnP5W61ABrjjxHc6RphZh11",
      value: 100000,
    },
    {
      scriptpubkey: "0014ad4cc1cc859c57477bf90d0f944360d90a3998bf",
      scriptpubkey_asm:
        "OP_0 OP_PUSHBYTES_20 ad4cc1cc859c57477bf90d0f944360d90a3998bf",
      scriptpubkey_type: "v0_p2wpkh",
      scriptpubkey_address: "bc1q44xvrny9n3t5w7lep58egsmqmy9rnx9lt6u0tc",
      value: 36977942,
    },
  ],
} as unknown as Transaction;

// const { serializedTx, serializedWTx } = txSerializer(
//   tx as unknown as Transaction
// );
// // console.log("serializedWTx", serializedWTx);
// // console.log(reversify(sha256(sha256(serializedTx))));
// // console.log(reversify(sha256(sha256(serializedWTx))));

// console.log(reversify(sha256(sha256(txSerializer(tx).serializedTx))));
// const txToBeSigned = txForSigning(tx, 0, SigHash.ALL);
// const hash = sha256(sha256(txToBeSigned));

// const pubkey = ECPair.fromPublicKey(
//   Buffer.from(
//     "022bf8c45da789f695d59f93983c813ec205203056e19ec5d3fbefa809af67e2ec",
//     "hex"
//   ),
//   { compressed: true }
// );

// const res = pubkey.verify(
//   Buffer.from(hash, "hex"),
//   Buffer.from(
//     extractRSFromSignature(
//       //extract r, s from DER encoded ECDSA signature
//       "30440220780ad409b4d13eb1882aaf2e7a53a206734aa302279d6859e254a7f0a7633556022011fd0cbdf5d4374513ef60f850b7059c6a093ab9e46beb002505b7cba0623cf301"
//     ),
//     "hex"
//   )
// );

// console.log(res);

// console.log(
//   reversify("b4948747cc3ddbc03e016c43d82087bf3fff63b856e887561005ec1acd2eb290")
// );

// console.log(res);

// p2pkh
//02000000|01|25c9f7c56ab4b9c358cb159175de542b41c7d38bf862a045fa5da51979e37ffb|01000000|6b|4830450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd012102c371793f2e19d1652408efef67704a2e9953a43a9dd54360d56fc93277a5667d|ffffffff|02|54e8050000000000|19|76a9141ef7874d338d24ecf6577e6eadeeee6cd579c67188ac|c891000000000000|19|76a9142e391b6c47778d35586b1f4154cbc6b06dc9840c88ac|00000000|
//p2wpkh
//version|witness|numInputs| input tx hash 1                             | input tx index 1 | scriptSig size | sequence|inputTxHash2                        |outputIndex2|scriptSig2|sequence2|num outputs| output value | output scriptpubkey size | output scriptpubkey
//01000000|0001|02|de4879b9137defa55479f365334d67e59ef146c0146a71e70161ef7e7cc65fb4|01000000|00|ffffffff|e7b2f24ec6fde8d97cab15e885e68b45899a06ba4385c753793ed6ceb3771d56|00000000|00|ffffffff|02|a0b67600|0000000022|0020e84d3f6e5cbdc0edf746db92890753c7cbb0a5d56e046be6015819f3b4bd8abc|552a|00000000000016|0014a8f98809869fce19104d18efad1273e891973687|02|47|304402203e6a1971bbf6c42136fc8dfcf11efa115472ae063d0345f446b6383c2f17380b02204b126ed182a51bb32f90276fea4c7c0b9a9ba22df5d2fde7d3c45c0b5542265601|21|02e7d637bf72bdd26390a93535e7f70d0dc3091fc0768ac973d82d94fa09c48da5|02|47|3044022072f357d0ab64f4c828579eb1e8626d9b938b3d2948766f94add00859338bcd1a02200a52417f8b556154a5112ab4445e42b0e28a64e09fe6bdea2712cb59e447056f01|21|02e7d637bf72bdd26390a93535e7f70d0dc3091fc0768ac973d82d94fa09c48da5|00000000
//p2wsh
//02000000|0001|01|30d1c40780728b4e30c53333fa7e38bd8ebed021c05ec135592ad17a078513a5|00000000|00|fdffffff|03|43721600|0000000022|0020d333523199087a0d8faad8667ba5540d93b7041ce0af2f10248565edb86a55fc|52e86d02|0000000022|0020af9746c91370a2132c85fad6641650e5c160f3522b748b15120d03695dcfd4c3|6e8cf000|0000000016|0014bb9daf27204b53a37612eace73520b0774c119f8|0548|3045022100f9beb9585cc5b8487264898c532c10c862d24b98a53688ddf2b6800bb049d6b2022001d3ce09fa560efafe553214356151dde3046463214939b34cf27500969c83fd01|21|030681010e3431c0a31da520cf46a2b2c1d645a0d486918139f7e3f8c7fda677ab|20|1769d10a9a7e8506e14edc4801e40cc24699ec4d4086ddcc186e33fe458470c6|01|01|5b|63a820406af310092ba4cc3d12b65d573c0acd25d63a97905c8cf38a77b524dee657e88876a914bb9daf27204b53a37612eace73520b0774c119f867022001b27576a9142c3debdb231b31b42a8877fc3b16de014b13f10b6888ac|00000000
//01000000000102
// input txhash1: de4879b9137defa55479f365334d67e59ef146c0146a71e70161ef7e7cc65fb4

// const j =
//   "01000000000101bb3b4760944489ec9bed5d5fb002f33b3dda278784d7faef371067e518c97d3b1000000000ffffffff02a0860100000000001976a9146085312a9c500ff9cc35b571b0a1e5efb7fb9f1688ac163d340200000000160014ad4cc1cc859c57477bf90d0f944360d90a3998bf024730440220780ad409b4d13eb1882aaf2e7a53a206734aa302279d6859e254a7f0a7633556022011fd0cbdf5d4374513ef60f850b7059c6a093ab9e46beb002505b7cba0623cf30121022bf8c45da789f695d59f93983c813ec205203056e19ec5d3fbefa809af67e2ec00000000";
// const a =
//   "01000000000101bb3b4760944489ec9bed5d5fb002f33b3dda278784d7faef371067e518c97d3b1000000000ffffffff02a0860100000000001976a9146085312a9c500ff9cc35b571b0a1e5efb7fb9f1688ac163d340200000000160014ad4cc1cc859c57477bf90d0f944360d90a3998bf028e30440220780ad409b4d13eb1882aaf2e7a53a206734aa302279d6859e254a7f0a7633556022011fd0cbdf5d4374513ef60f850b7059c6a093ab9e46beb002505b7cba0623cf30142022bf8c45da789f695d59f93983c813ec205203056e19ec5d3fbefa809af67e2ec00000000";

// for (let i = 0; i < j.length; i++) {
//   if (j[i] !== a[i]) {
//     console.log(a.slice(i));
//     console.log(i);
//   }
// }
