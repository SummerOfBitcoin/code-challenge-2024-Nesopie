import { Transaction } from "../../types";
import { txWeight } from "../encoding/serializer";

export const totalFee = (txs: Transaction[]) => {
  let inputValues = 0;
  let outputValues = 0;

  for (const tx of txs) {
    for (const input of tx.vin) {
      inputValues += input.prevout.value;
    }
    for (const output of tx.vout) {
      outputValues += output.value;
    }
  }

  return inputValues - outputValues;
};

export const feePerByte = (tx: Transaction) => {
  let fee = 0;
  for (const input of tx.vin) {
    fee += input.prevout.value;
  }

  for (const output of tx.vout) {
    fee -= output.value;
  }

  return fee / txWeight(tx);
};
