import { TransactionType } from "../../types";
import { FALSE } from "../script/constants";
import { ScriptStack } from "../script/stack";
import { Transaction } from "../transaction";

import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";

const ECPair = ECPairFactory(ecc);

export const ScriptValidator = (tx: Transaction) => {
  for (let i = 0; i < tx.vin.length; i++) {
    const input = tx.vin[i];
    if (!input.prevout) continue;

    switch (input.prevout.scriptpubkey_type) {
      case TransactionType.P2SH: {
        const script = new ScriptStack(tx, i);
        script.execute(input.scriptsig);
        script.execute(input.prevout.scriptpubkey);
        if (script.top() === FALSE) return false;

        script.clear();

        if (input.witness) {
          if (input.scriptsig.length === 70) {
            for (let i = 0; i < input.witness.length - 1; i++) {
              if (input.witness[i] === "") script.push(FALSE);
              else script.push(input.witness[i]);
            }

            try {
              script.execute(input.witness[input.witness.length - 1]); //final value of the witness is the redeem script
              if (script.top() === FALSE) return false;
            } catch (err) {
              console.log(i);
              console.log((err as Error).message);
              return false;
            }
          } else continue;
        }

        break;
      }
      case TransactionType.P2WSH: {
        const script = new ScriptStack(tx, i);
        if (!input.witness) return false;
        for (let i = 0; i < input.witness.length - 1; i++) {
          if (input.witness[i] === "") script.push(FALSE);
          else script.push(input.witness[i]);
        }
        try {
          script.execute(input.witness[input.witness.length - 1]); //final value of the witness is the redeem script
          if (script.top() === FALSE) return false;
        } catch (err) {
          console.log(i);
          console.log((err as Error).message);
          return false;
        }
        break;
      }
      default: {
        continue;
      }
    }
  }
  return true;
};
