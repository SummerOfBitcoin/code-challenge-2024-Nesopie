//validates the length of the scriptpubkeyaddress

import { TransactionType } from "../../types";
import { Transaction } from "../transaction";
import base58 from "bs58check";
import { bech32, bech32m } from "bech32";

//validate the length of the scriptpubkey
//validate the address, base58, bech32, bech32m
export const MetadataValidator = (tx: Transaction) => {
  for (const input of tx.vin) {
    if (!input.prevout) continue;
    if (input.prevout.scriptpubkey.length <= 0) return false;
    switch (input.prevout.scriptpubkey_type) {
      case TransactionType.P2PKH: {
        if (input.prevout.scriptpubkey.length !== 50) return false;
        const spk = input.prevout.scriptpubkey;
        const pkh = spk.slice(3 * 2, spk.length - 2 * 2);
        const validAddress =
          base58.encode(Buffer.from("00" + pkh, "hex")) ===
          input.prevout.scriptpubkey_address;
        if (!validAddress) return false;
        break;
      }
      case TransactionType.P2SH: {
        if (input.prevout.scriptpubkey.length !== 46) return false;
        const spk = input.prevout.scriptpubkey;
        const sh = spk.slice(2 * 2, spk.length - 1 * 2);
        const validAddress =
          base58.encode(Buffer.from("05" + sh, "hex")) ===
          input.prevout.scriptpubkey_address;
        if (!validAddress) return false;
        break;
      }
      case TransactionType.P2WPKH: {
        if (input.prevout.scriptpubkey.length !== 44) return false;
        if (!input.witness || input.witness.length !== 2) return false;

        const spk = input.prevout.scriptpubkey;
        const pkh = spk.slice(2 * 2);
        const validAddress =
          bech32.encode("bc", [
            0,
            ...bech32.toWords(Buffer.from(pkh, "hex")),
          ]) == input.prevout.scriptpubkey_address;
        if (!validAddress) return false;

        break;
      }
      case TransactionType.P2WSH: {
        if (input.prevout.scriptpubkey.length !== 68) return false;
        const spk = input.prevout.scriptpubkey;
        const wsh = spk.slice(2 * 2);
        const validAddress =
          bech32.encode("bc", [
            0,
            ...bech32.toWords(Buffer.from(wsh, "hex")),
          ]) == input.prevout.scriptpubkey_address;
        if (!validAddress) return false;

        break;
      }
      case TransactionType.P2TR: {
        if (input.prevout.scriptpubkey.length !== 68) return false;
        const spk = input.prevout.scriptpubkey;
        const pk = spk.slice(2 * 2);
        const validAddress =
          bech32m.encode("bc", [
            1,
            ...bech32m.toWords(Buffer.from(pk, "hex")),
          ]) == input.prevout.scriptpubkey_address;
        if (!validAddress) return false;
        break;
      }
    }
  }

  if (tx.fee < 0) return false;

  return true;
};
