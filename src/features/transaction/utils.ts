import { compactSize } from "../encoding/compactSize";
import { Serializer } from "../encoding/serializer";
import { Transaction } from "./transaction";

const sizeMultiplier = (val: Buffer | string, multiplier: number) => {
  return val instanceof Buffer
    ? (val.toString("hex").length / 2) * multiplier
    : (val.length / 2) * multiplier;
};

export const calculateWeight = (tx: Transaction, isSegwit: boolean = false) => {
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

  return isSegwit ? nonSegwitWeight + segwitWeight : nonSegwitWeight;
};
