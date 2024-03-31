import { Transaction, Input, Output } from "../transaction";
import { hash160, hash256, reversify, sha256 } from "../../utils";
import { compactSize } from "./compactSize";
import { getNextNBytes } from "../script/utils";
import { SigHash } from "../../types";
import { Errors } from "./errors";
import { TEMPLATES } from "./witnessTemplates";
import { ZERO } from "../../constants";

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

  static serializeWitness(tx: Transaction, index: number, sighash: SigHash) {
    let serializedWTx = "";

    const version = Buffer.alloc(4);
    version.writeUint32LE(tx.version, 0);

    let prevouts = "";
    let sequences = "";
    let hashPrevouts = "";
    let hashSequence = "";
    if (sighash >= SigHash.ANYONE_CAN_PAY) hashPrevouts = ZERO;
    else {
      for (const input of tx.vin) {
        prevouts += reversify(input.txid);
        const prevoutVout = Buffer.alloc(4);
        prevoutVout.writeUint32LE(input.vout, 0);
        prevouts += prevoutVout.toString("hex");
      }
      hashPrevouts = hash256(prevouts);
    }

    if (
      sighash >= SigHash.ANYONE_CAN_PAY ||
      sighash === SigHash.SINGLE ||
      sighash === SigHash.NONE
    )
      hashSequence = ZERO;
    else {
      for (const input of tx.vin) {
        const sequence = Buffer.alloc(4);
        sequence.writeUint32LE(input.sequence, 0);
        sequences += sequence.toString("hex");
      }
      hashSequence = hash256(sequences);
    }

    let outputs = "";
    let hashOutputs = "";
    if (
      (sighash & 0x1f) === SigHash.SINGLE ||
      (sighash & 0x1f) === SigHash.NONE
    ) {
      if ((sighash & 0x1f) === SigHash.SINGLE && index < tx.vout.length) {
        hashOutputs = hash256(tx.vout[index].serialize());
      } else hashOutputs = ZERO;
    } else {
      for (const output of tx.vout) {
        outputs += output.serialize();
      }
      hashOutputs = hash256(outputs);
    }

    const input = tx.vin[index];
    if (!input) throw new Error(Errors.INVALID_VOUT);
    const vout = Buffer.alloc(4);
    vout.writeUint32LE(input.vout, 0);
    const outpoint = reversify(input.txid) + vout.toString("hex");

    if (!input.witness) throw new Error(Errors.INVALID_WITNESS);
    if (!input.witness[1]) throw new Error(Errors.PUBKEY_NOT_FOUND);
    const scriptCode = TEMPLATES.P2WPKH(hash160(input.witness[1]));

    if (!input.prevout) throw new Error(Errors.INVALID_PREVOUT);
    const amount = Buffer.alloc(8);
    amount.writeBigInt64LE(BigInt(input.prevout.value), 0);

    const nSequence = Buffer.alloc(4);
    nSequence.writeUint32LE(input.sequence, 0);

    const nLocktime = Buffer.alloc(4);
    nLocktime.writeUint32LE(tx.locktime, 0);

    const hashcode = Buffer.alloc(4);
    hashcode.writeUint32LE(sighash, 0);

    serializedWTx += version.toString("hex");
    serializedWTx += hashPrevouts;
    serializedWTx += hashSequence;
    serializedWTx += outpoint;
    serializedWTx += scriptCode;
    serializedWTx += amount.toString("hex");
    serializedWTx += nSequence.toString("hex");
    serializedWTx += hashOutputs;
    serializedWTx += nLocktime.toString("hex");
    serializedWTx += hashcode.toString("hex");

    return serializedWTx;
  }
}

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
