//validates the length of the scriptpubkeyaddress

import { Transaction, TransactionType } from "../../types";

//validate the length of the scriptpubkey
export const LengthValidator = (tx: Transaction) => {
  for (const input of tx.vin) {
    if (input.prevout.scriptpubkey.length <= 0) return false;
    switch (input.prevout.scriptpubkey_type) {
      case TransactionType.P2PKH:
        if (input.prevout.scriptpubkey.length !== 50) {
          return false;
        }
        break;
      case TransactionType.P2SH:
        break;
      case TransactionType.P2WPKH:
        if (input.prevout.scriptpubkey.length !== 44) {
          return false;
        }
        if (input.witness.length !== 2) return false;
        break;
      case TransactionType.P2WSH:
        break;
      case TransactionType.P2TR:
        if (input.prevout.scriptpubkey.length !== 68) {
          return false;
        }
        break;
    }
  }
  return true;
};
