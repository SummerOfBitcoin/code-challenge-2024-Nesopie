import { Transaction } from "../../types";
import { reversify, sha256 } from "../../utils";
import { txSerializer } from "../encoding/serializer";

export const merkleRoot = (txs: string[]) => {
  let curr = txs;

  while (curr.length > 1) {
    let next = [];

    if (curr.length % 2 === 1) curr = [...curr, curr[curr.length - 1]];
    for (let i = 0; i < curr.length; i += 2) {
      next.push(sha256(sha256(curr[i] + curr[i + 1])));
    }
    curr = next;
  }

  return curr[0];
};
