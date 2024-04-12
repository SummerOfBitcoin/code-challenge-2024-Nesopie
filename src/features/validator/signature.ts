import { SigHash, TransactionType } from "../../types";
import { Transaction } from "../transaction";
import { hash160, hash256, sha256, taprootHash } from "../../utils";
import * as asn1js from "asn1js";

import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";
import { getNextNBytes } from "../script/utils";
import {
  SECP256K1_ORDER,
  TAP_BRANCH,
  TAP_LEAF,
  TAP_SIG_HASH,
  TAP_TWEAK,
} from "../../constants";
import { compactSize } from "../encoding/compactSize";

const ECPair = ECPairFactory(ecc);

const removePadding = (r: string, s: string) => {
  //remove der padding if length === 66
  if (r.length === 66) {
    r = r.slice(2);
  }
  if (s.length === 66) {
    s = s.slice(2);
  }

  //add padding to make it 32 bytes for ecpair
  r = r.padStart(64, "0");
  s = s.padStart(64, "0");

  return r + s;
};

export const extractSighashFromSignature = (signature: string) => {
  return parseInt(signature.slice(signature.length - 2), 16) as SigHash;
};

export const signatureFromDER = (derEncodedSignature: string) => {
  const asn1 = asn1js.fromBER(Buffer.from(derEncodedSignature, "hex"));

  let r = Buffer.from(
    (asn1.result.valueBlock as any).value[0].valueBlock.valueHexView
  ).toString("hex");
  let s = Buffer.from(
    (asn1.result.valueBlock as any).value[1].valueBlock.valueHexView
  ).toString("hex");

  const signature = removePadding(r, s);
  return signature;
};

export const signatureValidator = (tx: Transaction): boolean => {
  for (let i = 0; i < tx.vin.length; i++) {
    const input = tx.vin[i];
    if (!input.prevout) return true; //there is nothing to validate
    switch (input.prevout.scriptpubkey_type) {
      case TransactionType.P2PKH: {
        const asmTokens = input.scriptsig_asm.split(" ");
        const derEncodedSignature = asmTokens[1];
        const pubkey = asmTokens[asmTokens.length - 1];

        const sighash = extractSighashFromSignature(derEncodedSignature);
        const signature = signatureFromDER(derEncodedSignature);

        const ecpair = ECPair.fromPublicKey(Buffer.from(pubkey, "hex"));

        const msg = tx.signWith(i, sighash, TransactionType.P2PKH);
        const hash = sha256(sha256(msg));
        const valid = ecpair.verify(
          Buffer.from(hash, "hex"),
          Buffer.from(signature, "hex")
        );
        if (!valid) return false;
        break;
      }

      case TransactionType.P2WPKH: {
        if (!input.witness) return false;
        const derEncodedSignature = input.witness[0];
        const pubkey = input.witness[1];
        const pubkeyHash = hash160(pubkey);
        const pubkeyInScript = input.prevout.scriptpubkey.slice(4);

        if (pubkeyHash !== pubkeyInScript) return false;

        const sighash = extractSighashFromSignature(derEncodedSignature);
        const signature = signatureFromDER(derEncodedSignature);

        const ecpair = ECPair.fromPublicKey(Buffer.from(pubkey, "hex"), {
          compressed: true,
        });

        const msg = tx.signWith(i, sighash, TransactionType.P2WPKH);
        const hash = hash256(msg);
        const valid = ecpair.verify(
          Buffer.from(hash, "hex"),
          Buffer.from(signature, "hex")
        );
        if (!valid) {
          console.log(input.txid, input.vout);
          return false;
        }
        break;
      }

      case TransactionType.P2SH: {
        // if (tx.isSegwit) {
        if (!input.witness) continue;
        if (input.scriptsig.length === 46) {
          const derEncodedSignature = input.witness[0];
          const pubkey = input.witness[1];

          const sighash = extractSighashFromSignature(derEncodedSignature);
          const signature = signatureFromDER(derEncodedSignature);

          const ecpair = ECPair.fromPublicKey(Buffer.from(pubkey, "hex"), {
            compressed: true,
          });
          const msg = tx.signWith(i, sighash, TransactionType.P2WPKH);
          const hash = hash256(msg);
          const valid = ecpair.verify(
            Buffer.from(hash, "hex"),
            Buffer.from(signature, "hex")
          );
          if (!valid) {
            return false;
          }
          break;
        } else if (input.scriptsig.length === 70) continue;
        else return false;
      }

      case TransactionType.P2TR: {
        if (!input.prevout.scriptpubkey) return false;

        const [_, tweakedPubkey] = getNextNBytes(input.prevout.scriptpubkey, 2);

        if (!input.witness) return false;

        const isAnnexPresent =
          input.witness.length > 1 &&
          input.witness[input.witness.length - 1].startsWith("50")
            ? 1
            : 0;
        if (input.witness.length <= 2) {
          //key path spending
          const signature =
            input.witness[input.witness.length - 1 - isAnnexPresent];
          const sighash =
            signature.length > 128
              ? extractSighashFromSignature(signature)
              : 0x00;
          const msg = tx.signWith(i, sighash, TransactionType.P2TR, 0);
          const taprootHashResult = taprootHash(TAP_SIG_HASH, "00" + msg);
          const ecpair = ECPair.fromPublicKey(
            Buffer.from("02" + tweakedPubkey, "hex")
          );

          const valid = ecpair.verifySchnorr(
            Buffer.from(taprootHashResult, "hex"),
            Buffer.from(signature.slice(0, 128), "hex")
          );

          if (!valid) console.log(i);
        } else {
          const script =
            input.witness[input.witness.length - 2 - isAnnexPresent]; //assuming that we took out the annex
          const controlBlock =
            input.witness[input.witness.length - 1 - isAnnexPresent];
          const controlBlockLength = controlBlock.length / 2;

          if ((controlBlockLength - 33) % 32 !== 0) {
            return false;
          }

          const m = (controlBlockLength - 33) / 32;

          const p = controlBlock.slice(2, 66);

          const v = (parseInt(controlBlock.slice(0, 2), 16) & 0xfe).toString(
            16
          );

          const k = [];
          k.push(
            taprootHash(
              TAP_LEAF,
              v +
                compactSize(BigInt(script.length / 2)).toString("hex") +
                script
            )
          );

          for (let i = 0; i < m; i++) {
            const e = controlBlock.slice((33 + 32 * i) * 2, (65 + 32 * i) * 2);
            const branches: [string, string] = e < k[i] ? [e, k[i]] : [k[i], e];

            k.push(taprootHash(TAP_BRANCH, branches[0] + branches[1]));
          }

          const t = taprootHash(TAP_TWEAK, p + k[m]);
          if (Buffer.from(t, "hex").compare(SECP256K1_ORDER) > 0) return false;

          const P = ecc.xOnlyPointFromPoint(Buffer.from("02" + p, "hex"));
          const Q = ecc.xOnlyPointAddTweak(P, Buffer.from(t, "hex"))!;

          if (Buffer.from(Q.xOnlyPubkey).toString("hex") !== tweakedPubkey)
            return false;
        }
      }
    }
  }

  return true;
};
