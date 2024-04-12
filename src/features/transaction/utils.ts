import { TransactionType } from "../../types";
import { compactSize } from "../encoding/compactSize";
import { Serializer } from "../encoding/serializer";
import { Transaction } from "./components/transaction";

const sizeMultiplier = (val: Buffer | string, multiplier: number) => {
  return val instanceof Buffer
    ? (val.toString("hex").length / 2) * multiplier
    : (val.length / 2) * multiplier;
};

export const calculateWeight = (tx: Transaction) => {
  let nonSegwitWeight = 0;

  const version = Buffer.alloc(4);
  version.writeInt16LE(tx.version, 0);
  nonSegwitWeight += sizeMultiplier(version, 4);

  let segwitWeight = 2; //for marker and flag as they are 1 byte each

  const numInputs = compactSize(BigInt(tx.vin.length));
  nonSegwitWeight += sizeMultiplier(numInputs, 4);

  for (let i = 0; i < tx.vin.length; i++) {
    nonSegwitWeight += sizeMultiplier(Serializer.serializeInput(tx.vin[i]), 4);
  }

  const numOutputs = compactSize(BigInt(tx.vout.length));
  nonSegwitWeight += sizeMultiplier(numOutputs, 4);
  for (let i = 0; i < tx.vout.length; i++) {
    nonSegwitWeight += sizeMultiplier(
      Serializer.serializeOutput(tx.vout[i]),
      4
    );
  }

  for (let i = 0; i < tx.vin.length; i++) {
    const input = tx.vin[i];
    if (
      !input.witness ||
      (input && input.witness && input.witness.length === 0)
    ) {
      segwitWeight += sizeMultiplier(compactSize(BigInt(0)), 1);
    } else {
      segwitWeight += sizeMultiplier(
        compactSize(BigInt(input.witness.length)),
        1
      );
      for (const witness of input.witness) {
        segwitWeight += sizeMultiplier(
          compactSize(BigInt(witness.length / 2)),
          1
        );
        segwitWeight += sizeMultiplier(witness, 1);
      }
    }
  }

  const locktime = Buffer.alloc(4);
  locktime.writeUint32LE(tx.locktime, 0);
  nonSegwitWeight += sizeMultiplier(locktime, 4);

  return tx.isSegwit ? nonSegwitWeight + segwitWeight : nonSegwitWeight;
};

export const getTransactionType = (tx: Transaction, index: number) => {
  const input = tx.vin[index];
  if (!input || !input.prevout) throw new Error("Invalid input");

  const transactionType = input.prevout.scriptpubkey_type as TransactionType;
  if (
    transactionType === TransactionType.P2TR ||
    transactionType === TransactionType.OP_RETURN ||
    transactionType === TransactionType.P2WSH ||
    transactionType === TransactionType.P2WPKH ||
    transactionType === TransactionType.P2PKH
  )
    return transactionType;

  if (!input.witness) return TransactionType.P2SH;

  if (input.scriptsig.length === 46) return TransactionType.P2WPKH;
  return TransactionType.P2WSH;
};
