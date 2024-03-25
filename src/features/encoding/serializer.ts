import { Transaction, Input, Output } from "../../types";
import { reversify, sha256 } from "../../utils";
import { compactSize } from "./compactSize";
import cloneDeep from "lodash.clonedeep";
import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";
import { bitcoin } from "ecpair/src/networks";
import { getNextNBytes } from "../script/utils";
import { ZEROS } from "../block/coinbaseTransaction";

const ECPair = ECPairFactory(ecc);

export const outputSerializer = (outTx: Output) => {
  const amount = Buffer.alloc(8);
  amount.writeBigInt64LE(BigInt(outTx.value), 0);
  return `${amount.toString("hex")}${compactSize(
    BigInt(outTx.scriptpubkey.length / 2)
  ).toString("hex")}${outTx.scriptpubkey}`;
};

export const inputSerializer = (inTx: Input) => {
  let serializedInput = "";

  const txHash = reversify(inTx.txid);
  serializedInput += txHash;

  const outputIndex = Buffer.alloc(4);
  outputIndex.writeUint32LE(inTx.vout, 0);
  serializedInput += outputIndex.toString("hex");

  const scriptSig = inTx.scriptsig;
  const scriptSigSize = compactSize(BigInt(scriptSig.length / 2));
  const sequence = Buffer.alloc(4);
  sequence.writeUint32LE(inTx.sequence, 0);

  serializedInput += scriptSigSize.toString("hex");
  serializedInput += scriptSig;
  serializedInput += sequence.toString("hex");

  return serializedInput;
};

export const txSerializer = (tx: Transaction) => {
  let serializedTx = "";
  let serializedWTx = "";

  const version = Buffer.alloc(4);
  version.writeInt16LE(tx.version, 0);
  serializedTx += version.toString("hex");
  serializedWTx += version.toString("hex");

  serializedWTx += "0001";

  const numInputs = compactSize(BigInt(tx.vin.length));
  serializedTx += numInputs.toString("hex");
  serializedWTx += numInputs.toString("hex");

  for (let i = 0; i < tx.vin.length; i++) {
    serializedTx += inputSerializer(tx.vin[i]);
    serializedWTx += inputSerializer(tx.vin[i]);
  }

  const numOutputs = compactSize(BigInt(tx.vout.length));
  serializedTx += numOutputs.toString("hex");
  serializedWTx += numOutputs.toString("hex");
  for (let i = 0; i < tx.vout.length; i++) {
    serializedTx += outputSerializer(tx.vout[i]);
    serializedWTx += outputSerializer(tx.vout[i]);
  }

  let isWitness = false;
  for (let i = 0; i < tx.vin.length; i++) {
    if (!tx.vin[i].witness || tx.vin[i].witness.length === 0) {
      serializedWTx += compactSize(BigInt(0)).toString("hex");
    } else {
      isWitness = true;
      serializedWTx += compactSize(BigInt(tx.vin[i].witness.length)).toString(
        "hex"
      );
      for (const witness of tx.vin[i].witness) {
        serializedWTx += compactSize(BigInt(witness.length / 2)).toString(
          "hex"
        );
        serializedWTx += witness;
      }
    }
  }

  const locktime = Buffer.alloc(4);
  locktime.writeUint32LE(tx.locktime, 0);
  serializedTx += locktime.toString("hex");
  serializedWTx += locktime.toString("hex");

  return {
    serializedTx,
    serializedWTx: isWitness
      ? tx.vin[0].txid === ZEROS
        ? ZEROS
        : serializedWTx
      : serializedTx,
  };
};

export const txWeight = (tx: Transaction) => {
  return txSerializer(tx).serializedTx.length / 2; // divide by two cuz 2 hex chars are 1 byte and 1e6 as you cconsider it in mb
};

const txForSigning = (tx: Transaction, input: number) => {
  const txCopy = cloneDeep(tx);
  for (let i = 0; i < txCopy.vin.length; i++) {
    if (i === input) {
      txCopy.vin[i].scriptsig = txCopy.vin[i].prevout.scriptpubkey;
    } else {
      txCopy.vin[i].scriptsig = "";
    }
  }

  return txSerializer(txCopy).serializedTx + "01000000"; //force SIGHASH_ALL
};

const extractRSFromSignature = (derEncodedSignature: string) => {
  let derEncodingScheme,
    signatureLength,
    r,
    s,
    rLength,
    sLength,
    rest,
    prefix,
    padding;
  [derEncodingScheme, rest] = getNextNBytes(derEncodedSignature, 1);
  if (derEncodingScheme !== "30")
    throw new Error("Invalid DER encoding scheme");
  [signatureLength, rest] = getNextNBytes(rest, 1);
  [prefix, rest] = getNextNBytes(rest, 1);
  [rLength, rest] = getNextNBytes(rest, 1);
  [r, rest] = getNextNBytes(rest, parseInt(rLength, 16));
  if (r.length === 66) [padding, r] = getNextNBytes(r, 1); //account for 00 padding
  [prefix, rest] = getNextNBytes(rest, 1);
  [sLength, rest] = getNextNBytes(rest, 1);
  [s, rest] = getNextNBytes(rest, parseInt(sLength, 16));
  return r + s;
};

// const tx = {
//   txid: "036da43312463ef1dff92d7c894a5362e07ff5b3111d1f166ba4cd91f3b142b7",
//   version: 1,
//   locktime: 0,
//   vin: [
//     {
//       txid: "29c1da61a7f859bfb198406cdaf333eb2dffb0878217e9a91b0451d225f3b985",
//       vout: 46,
//       prevout: {
//         scriptpubkey: "76a914b93e0466997c5ffa7daec8a39746f34c8756ce7788ac",
//         scriptpubkey_asm:
//           "OP_DUP OP_HASH160 OP_PUSHBYTES_20 b93e0466997c5ffa7daec8a39746f34c8756ce77 OP_EQUALVERIFY OP_CHECKSIG",
//         scriptpubkey_type: "p2pkh",
//         scriptpubkey_address: "1HtUJX5U3kh6dqFNmkzBrqmEFvyoVwLrN7",
//         value: 115216,
//       },
//       scriptsig:
//         "4830450221009ef1e4141890b2a16a788a0ea04bb0133c02ec507649e65e576d6e372cd123020220765c2cfef1ce59ea5e064797d9dbfdcb00f83371f21af06f5b3b91d23717df2e814104019fab1f0b85b95be4905a712e73415cbddb84a1dbb06653e7f9f68782ece6fc630ee111f10ba7cb0dabfe44b899018df73f541368d375f62fe82968eb404adc",
//       scriptsig_asm:
//         "OP_PUSHBYTES_72 30450221009ef1e4141890b2a16a788a0ea04bb0133c02ec507649e65e576d6e372cd123020220765c2cfef1ce59ea5e064797d9dbfdcb00f83371f21af06f5b3b91d23717df2e81 OP_PUSHBYTES_65 04019fab1f0b85b95be4905a712e73415cbddb84a1dbb06653e7f9f68782ece6fc630ee111f10ba7cb0dabfe44b899018df73f541368d375f62fe82968eb404adc",
//       is_coinbase: false,
//       sequence: 4294967295,
//     },
//     {
//       txid: "29c1da61a7f859bfb198406cdaf333eb2dffb0878217e9a91b0451d225f3b985",
//       vout: 937,
//       prevout: {
//         scriptpubkey: "76a9147208148561e8ce36eb6961fde13c6e507c646b9588ac",
//         scriptpubkey_asm:
//           "OP_DUP OP_HASH160 OP_PUSHBYTES_20 7208148561e8ce36eb6961fde13c6e507c646b95 OP_EQUALVERIFY OP_CHECKSIG",
//         scriptpubkey_type: "p2pkh",
//         scriptpubkey_address: "1BPwiHhyyXMuFQJ4J2aU52anNM4j1GfVjY",
//         value: 106018,
//       },
//       scriptsig:
//         "483045022100ffc0e60d71e03701a4b8b17e19fae07f490929611bad0a7b1b60f02af141efd202201d1b56818d0edbbaf652478134b62e09510d1c41ec4d97eeec52014f379826bc8141049fd33ff7c01fd6f17e10bd220f7f64abc179ae6386b239d91ab8080e335c83f92b7a0e7d2e7127f3fdaf466b5ddc9fa645f9579385dbfb4bbbe76ad028300adc",
//       scriptsig_asm:
//         "OP_PUSHBYTES_72 3045022100ffc0e60d71e03701a4b8b17e19fae07f490929611bad0a7b1b60f02af141efd202201d1b56818d0edbbaf652478134b62e09510d1c41ec4d97eeec52014f379826bc81 OP_PUSHBYTES_65 049fd33ff7c01fd6f17e10bd220f7f64abc179ae6386b239d91ab8080e335c83f92b7a0e7d2e7127f3fdaf466b5ddc9fa645f9579385dbfb4bbbe76ad028300adc",
//       is_coinbase: false,
//       sequence: 4294967295,
//     },
//     {
//       txid: "2cebf56a421673294603c5e1fbebd269fd74b30a6a3fdd48acbdbbca26b0225c",
//       vout: 525,
//       prevout: {
//         scriptpubkey: "76a914571e43b6fe5098e761e86dfdde5e8e219eceb92988ac",
//         scriptpubkey_asm:
//           "OP_DUP OP_HASH160 OP_PUSHBYTES_20 571e43b6fe5098e761e86dfdde5e8e219eceb929 OP_EQUALVERIFY OP_CHECKSIG",
//         scriptpubkey_type: "p2pkh",
//         scriptpubkey_address: "18we3WFb3CpPBkkzCbBUcCSPKiVHrJYfPy",
//         value: 111225,
//       },
//       scriptsig:
//         "483045022100839d571b36720b7d10a0155caca8653b7d62a996b620ed29657c4b68eb3b9345022004f9ffd2f917825137d5e98a19b5294bc0c1e5c5f9f33172f953e3a75a763703814104a5e3ae2399d6aa527ec7f5bffc40e3dd5d4b9dc2d4f8c91e001f2d179042e144ca509b45f592e4f7cad65063a7fdfae757e19c2a39dce682e56f3179ad8387e3",
//       scriptsig_asm:
//         "OP_PUSHBYTES_72 3045022100839d571b36720b7d10a0155caca8653b7d62a996b620ed29657c4b68eb3b9345022004f9ffd2f917825137d5e98a19b5294bc0c1e5c5f9f33172f953e3a75a76370381 OP_PUSHBYTES_65 04a5e3ae2399d6aa527ec7f5bffc40e3dd5d4b9dc2d4f8c91e001f2d179042e144ca509b45f592e4f7cad65063a7fdfae757e19c2a39dce682e56f3179ad8387e3",
//       is_coinbase: false,
//       sequence: 4294967295,
//     },
//     {
//       txid: "ced733236cd304eafcdbb10bfce1662d9f9ea6a8c3ca5f1fb9a61a67645c7ce6",
//       vout: 0,
//       prevout: {
//         scriptpubkey: "76a914dfe6561dd4df2de04037168b7a84705d48fcec1988ac",
//         scriptpubkey_asm:
//           "OP_DUP OP_HASH160 OP_PUSHBYTES_20 dfe6561dd4df2de04037168b7a84705d48fcec19 OP_EQUALVERIFY OP_CHECKSIG",
//         scriptpubkey_type: "p2pkh",
//         scriptpubkey_address: "1MQscqDZ5S7uGsPXGBkGQS3GqDjd1rKQvE",
//         value: 11761,
//       },
//       scriptsig:
//         "483045022100daa4d98a46efb36a668b6ceec2d076ef80ae16fc754aec0ed0ecef536e6d565d02204b130560491ef754730ad87aa15f6f98ed48fa354be84ea796639ca2287ccba18141044591aa390ae7e5329fe8b29ba367c7e4fa65ec7147d727139862ac53ec25981c18a2826a89bc2a6fd19dae27328855cb8ffc37307c8634930e7ed81ce05a94c8",
//       scriptsig_asm:
//         "OP_PUSHBYTES_72 3045022100daa4d98a46efb36a668b6ceec2d076ef80ae16fc754aec0ed0ecef536e6d565d02204b130560491ef754730ad87aa15f6f98ed48fa354be84ea796639ca2287ccba181 OP_PUSHBYTES_65 044591aa390ae7e5329fe8b29ba367c7e4fa65ec7147d727139862ac53ec25981c18a2826a89bc2a6fd19dae27328855cb8ffc37307c8634930e7ed81ce05a94c8",
//       is_coinbase: false,
//       sequence: 4294967295,
//     },
//     {
//       txid: "14de8d61ae9bc01491862372a909ba5ac8ec38941ccc8e2831f5f79a0951f529",
//       vout: 275,
//       prevout: {
//         scriptpubkey: "76a914dd67ab7c4fa493e6e9eac33f3f72827d2109fde988ac",
//         scriptpubkey_asm:
//           "OP_DUP OP_HASH160 OP_PUSHBYTES_20 dd67ab7c4fa493e6e9eac33f3f72827d2109fde9 OP_EQUALVERIFY OP_CHECKSIG",
//         scriptpubkey_type: "p2pkh",
//         scriptpubkey_address: "1MBgXWBJZyPvCrTL56Jf533bHnET9RCd8L",
//         value: 130541,
//       },
//       scriptsig:
//         "473044022042bb90214771653e6511a64d22136e0b4001f5077724d461f17134c8fb38609b02206a23c74ca8879984e1aa617b918289a630f1a47a1c525534ece0506b89ea3df2814104844ecaf938d1610c746155ff15571e63ad890e3bdb51c2adabd7d5399a8a403877e0f92d5abb8bee5bb753e9fb622dc7449de58b830ea208f0b63ab2a663b072",
//       scriptsig_asm:
//         "OP_PUSHBYTES_71 3044022042bb90214771653e6511a64d22136e0b4001f5077724d461f17134c8fb38609b02206a23c74ca8879984e1aa617b918289a630f1a47a1c525534ece0506b89ea3df281 OP_PUSHBYTES_65 04844ecaf938d1610c746155ff15571e63ad890e3bdb51c2adabd7d5399a8a403877e0f92d5abb8bee5bb753e9fb622dc7449de58b830ea208f0b63ab2a663b072",
//       is_coinbase: false,
//       sequence: 4294967295,
//     },
//     {
//       txid: "2cebf56a421673294603c5e1fbebd269fd74b30a6a3fdd48acbdbbca26b0225c",
//       vout: 409,
//       prevout: {
//         scriptpubkey: "76a914dd67ab7c4fa493e6e9eac33f3f72827d2109fde988ac",
//         scriptpubkey_asm:
//           "OP_DUP OP_HASH160 OP_PUSHBYTES_20 dd67ab7c4fa493e6e9eac33f3f72827d2109fde9 OP_EQUALVERIFY OP_CHECKSIG",
//         scriptpubkey_type: "p2pkh",
//         scriptpubkey_address: "1MBgXWBJZyPvCrTL56Jf533bHnET9RCd8L",
//         value: 108089,
//       },
//       scriptsig:
//         "483045022100a1d233643d1e39211b681f2cf407c21472beb4303da6f6111bdf2de96191803b022047754e545a4d97ac32b2c7b9c4e23d2a2121ab9a299414ad03d5f6b52a28a33b814104844ecaf938d1610c746155ff15571e63ad890e3bdb51c2adabd7d5399a8a403877e0f92d5abb8bee5bb753e9fb622dc7449de58b830ea208f0b63ab2a663b072",
//       scriptsig_asm:
//         "OP_PUSHBYTES_72 3045022100a1d233643d1e39211b681f2cf407c21472beb4303da6f6111bdf2de96191803b022047754e545a4d97ac32b2c7b9c4e23d2a2121ab9a299414ad03d5f6b52a28a33b81 OP_PUSHBYTES_65 04844ecaf938d1610c746155ff15571e63ad890e3bdb51c2adabd7d5399a8a403877e0f92d5abb8bee5bb753e9fb622dc7449de58b830ea208f0b63ab2a663b072",
//       is_coinbase: false,
//       sequence: 4294967295,
//     },
//   ],
//   vout: [
//     {
//       scriptpubkey: "76a914dba129909f56d7c889872cc691a4f8ff5c59f6fe88ac",
//       scriptpubkey_asm:
//         "OP_DUP OP_HASH160 OP_PUSHBYTES_20 dba129909f56d7c889872cc691a4f8ff5c59f6fe OP_EQUALVERIFY OP_CHECKSIG",
//       scriptpubkey_type: "p2pkh",
//       scriptpubkey_address: "1M2J3mZ53hf7GPMPPy8EPzEymdGW8cm9u6",
//       value: 554914,
//     },
//   ],
//   size: 1123,
//   weight: 4492,
//   fee: 27936,
//   status: {
//     confirmed: true,
//     block_height: 834638,
//     block_hash:
//       "000000000000000000025f742c626208ac87e0b7d15054abb4a19ca2d735a54e",
//     block_time: 1710405325,
//   },
//   hex: "010000000685b9f325d251041ba9e9178287b0ff2deb33f3da6c4098b1bf59f8a761dac1292e0000008b4830450221009ef1e4141890b2a16a788a0ea04bb0133c02ec507649e65e576d6e372cd123020220765c2cfef1ce59ea5e064797d9dbfdcb00f83371f21af06f5b3b91d23717df2e814104019fab1f0b85b95be4905a712e73415cbddb84a1dbb06653e7f9f68782ece6fc630ee111f10ba7cb0dabfe44b899018df73f541368d375f62fe82968eb404adcffffffff85b9f325d251041ba9e9178287b0ff2deb33f3da6c4098b1bf59f8a761dac129a90300008b483045022100ffc0e60d71e03701a4b8b17e19fae07f490929611bad0a7b1b60f02af141efd202201d1b56818d0edbbaf652478134b62e09510d1c41ec4d97eeec52014f379826bc8141049fd33ff7c01fd6f17e10bd220f7f64abc179ae6386b239d91ab8080e335c83f92b7a0e7d2e7127f3fdaf466b5ddc9fa645f9579385dbfb4bbbe76ad028300adcffffffff5c22b026cabbbdac48dd3f6a0ab374fd69d2ebfbe1c50346297316426af5eb2c0d0200008b483045022100839d571b36720b7d10a0155caca8653b7d62a996b620ed29657c4b68eb3b9345022004f9ffd2f917825137d5e98a19b5294bc0c1e5c5f9f33172f953e3a75a763703814104a5e3ae2399d6aa527ec7f5bffc40e3dd5d4b9dc2d4f8c91e001f2d179042e144ca509b45f592e4f7cad65063a7fdfae757e19c2a39dce682e56f3179ad8387e3ffffffffe67c5c64671aa6b91f5fcac3a8a69e9f2d66e1fc0bb1dbfcea04d36c2333d7ce000000008b483045022100daa4d98a46efb36a668b6ceec2d076ef80ae16fc754aec0ed0ecef536e6d565d02204b130560491ef754730ad87aa15f6f98ed48fa354be84ea796639ca2287ccba18141044591aa390ae7e5329fe8b29ba367c7e4fa65ec7147d727139862ac53ec25981c18a2826a89bc2a6fd19dae27328855cb8ffc37307c8634930e7ed81ce05a94c8ffffffff29f551099af7f531288ecc1c9438ecc85aba09a97223869114c09bae618dde14130100008a473044022042bb90214771653e6511a64d22136e0b4001f5077724d461f17134c8fb38609b02206a23c74ca8879984e1aa617b918289a630f1a47a1c525534ece0506b89ea3df2814104844ecaf938d1610c746155ff15571e63ad890e3bdb51c2adabd7d5399a8a403877e0f92d5abb8bee5bb753e9fb622dc7449de58b830ea208f0b63ab2a663b072ffffffff5c22b026cabbbdac48dd3f6a0ab374fd69d2ebfbe1c50346297316426af5eb2c990100008b483045022100a1d233643d1e39211b681f2cf407c21472beb4303da6f6111bdf2de96191803b022047754e545a4d97ac32b2c7b9c4e23d2a2121ab9a299414ad03d5f6b52a28a33b814104844ecaf938d1610c746155ff15571e63ad890e3bdb51c2adabd7d5399a8a403877e0f92d5abb8bee5bb753e9fb622dc7449de58b830ea208f0b63ab2a663b072ffffffff01a2770800000000001976a914dba129909f56d7c889872cc691a4f8ff5c59f6fe88ac00000000",
// } as unknown as Transaction;

const tx = {
  version: 2,
  locktime: 0,
  vin: [
    {
      txid: "fb7fe37919a55dfa45a062f88bd3c7412b54de759115cb58c3b9b46ac5f7c925",
      vout: 1,
      prevout: {
        scriptpubkey: "76a914286eb663201959fb12eff504329080e4c56ae28788ac",
        scriptpubkey_asm:
          "OP_DUP OP_HASH160 OP_PUSHBYTES_20 286eb663201959fb12eff504329080e4c56ae287 OP_EQUALVERIFY OP_CHECKSIG",
        scriptpubkey_type: "p2pkh",
        scriptpubkey_address: "14gnf7L2DjBYKFuWb6iftBoWE9hmAoFbcF",
        value: 433833,
      },
      scriptsig:
        "4830450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd012102c371793f2e19d1652408efef67704a2e9953a43a9dd54360d56fc93277a5667d",
      scriptsig_asm:
        "OP_PUSHBYTES_72 30450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd01 OP_PUSHBYTES_33 02c371793f2e19d1652408efef67704a2e9953a43a9dd54360d56fc93277a5667d",
      is_coinbase: false,
      sequence: 4294967295,
    },
  ],
  vout: [
    {
      scriptpubkey: "76a9141ef7874d338d24ecf6577e6eadeeee6cd579c67188ac",
      scriptpubkey_asm:
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 1ef7874d338d24ecf6577e6eadeeee6cd579c671 OP_EQUALVERIFY OP_CHECKSIG",
      scriptpubkey_type: "p2pkh",
      scriptpubkey_address: "13pjoLcRKqhzPCbJgYW77LSFCcuwmHN2qA",
      value: 387156,
    },
    {
      scriptpubkey: "76a9142e391b6c47778d35586b1f4154cbc6b06dc9840c88ac",
      scriptpubkey_asm:
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 2e391b6c47778d35586b1f4154cbc6b06dc9840c OP_EQUALVERIFY OP_CHECKSIG",
      scriptpubkey_type: "p2pkh",
      scriptpubkey_address: "15DQVhQ7PU6VPsTtvwLxfDsTP4P6A3Z5vP",
      value: 37320,
    },
  ],
} as unknown as Transaction;

// const { serializedTx, serializedWTx } = txSerializer(
//   tx as unknown as Transaction
// );
// console.log("serializedWTx", serializedWTx);
// console.log(reversify(sha256(sha256(serializedTx))));
// console.log(reversify(sha256(sha256(serializedWTx))));

// console.log(txSerializer(tx));
const txToBeSigned = txForSigning(tx, 0);
const hash = sha256(sha256(txToBeSigned));

const pubkey = ECPair.fromPublicKey(
  Buffer.from(
    "02c371793f2e19d1652408efef67704a2e9953a43a9dd54360d56fc93277a5667d",
    "hex"
  ),
  { compressed: false, network: bitcoin }
);

console.log(
  extractRSFromSignature(
    "30450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd01"
  )
);

const res = pubkey.verify(
  Buffer.from(hash, "hex"),
  Buffer.from(
    extractRSFromSignature(
      //extract r, s from DER encoded ECDSA signature
      "30450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd01"
    ),
    "hex"
  )
);

console.log(res);

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
