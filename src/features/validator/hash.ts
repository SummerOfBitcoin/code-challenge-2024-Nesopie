import { TransactionType } from "../../types";
import { hash160, sha256 } from "../../utils";
import { OP_CODES } from "../script/op_codes";
import { Transaction } from "../transaction";

//in p2sh p2wsh
//sha256(inner witness script) = last part of inneer redeem script
//hash160 of the inner redeem script should be equal to the hash in the script pubkey
//eg 0d9ef76964c23e940ebcddde868c1089dfdb52147364da01ee92438dfb7c9375

//in p2sh p2wpkh
// eg 3d2020595c0b78c6a269689dde42f7d5a39b4b6558d86643e7a9b0b976d672bf

export const HashValidator = (tx: Transaction) => {
  for (const input of tx.vin) {
    if (!input.prevout) continue;
    switch (input.prevout.scriptpubkey_type) {
      case TransactionType.P2PKH: {
        const scriptAsmTokens = input.scriptsig_asm.split(" ");
        const publicKey = scriptAsmTokens[scriptAsmTokens.length - 1];

        const hash = hash160(publicKey);

        const lockingScript = input.prevout.scriptpubkey;
        const script = `${OP_CODES.OP_DUP}${OP_CODES.OP_HASH160}${OP_CODES.OP_PUSHBYTES_20}${hash}${OP_CODES.OP_EQUALVERIFY}${OP_CODES.OP_CHECKSIG}`;

        if (script !== lockingScript) return false;
        break;
      }
      case TransactionType.P2SH: {
        const asmTokens = input.scriptsig_asm.split(" ");
        const hex = asmTokens[asmTokens.length - 1];
        const lockingScript = input.prevout.scriptpubkey;

        const scriptHash = hash160(hex);

        const script = `${OP_CODES.OP_HASH160}${OP_CODES.OP_PUSHBYTES_20}${scriptHash}${OP_CODES.OP_EQUAL}`;
        if (script !== lockingScript) {
          return false;
        }

        if (tx.isSegwit) {
          if (!input.witness) continue;
          if (input.scriptsig.length === 46) {
            //p2sh-p2wpkh
            const pubkeyHash = hash160(input.witness[input.witness.length - 1]);
            const scriptsig = `${OP_CODES.OP_PUSHBYTES_22}${OP_CODES.OP_0}${OP_CODES.OP_PUSHBYTES_20}${pubkeyHash}`;
            if (scriptsig !== input.scriptsig) return false;
          } else if (input.scriptsig.length === 70) {
            //p2sh-p2wsh
            const witnessScriptHash = sha256(
              input.witness[input.witness.length - 1]
            );
            const scriptsig = `${OP_CODES.OP_PUSHBYTES_34}${OP_CODES.OP_0}${OP_CODES.OP_PUSHBYTES_32}${witnessScriptHash}`;
            if (scriptsig !== input.scriptsig) return false;
          } else {
            return false;
          }
        }

        break;
      }
      case TransactionType.P2WPKH: {
        if (!input.witness || !input.witness[1]) return false;
        const publicKey = input.witness[1];

        const hash = hash160(publicKey);
        const lockingScript = input.prevout.scriptpubkey;
        const script = `${OP_CODES.OP_0}${OP_CODES.OP_PUSHBYTES_20}${hash}`;

        if (script !== lockingScript) return false;
        break;
      }
      case TransactionType.P2WSH: {
        if (!input.witness) return false;
        const witnessScript = input.witness[input.witness.length - 1];
        if (!witnessScript) return false;

        const lockingScript = input.prevout.scriptpubkey;
        const script = `${OP_CODES.OP_0}${OP_CODES.OP_PUSHBYTES_32}${sha256(
          witnessScript
        )}`;
        if (script !== lockingScript) return false;
        break;
      }
    }
  }

  return true;
};
