import { Transaction } from "../../types";
import { compactSize } from "../encoding/compactSize";

export const ZEROS =
  "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_VALUE = 0xffffffff;
const height = 538403;
const blockReward = 1250000000;

const coinbaseTemplate = {
  version: 0,
  locktime: 0,
  vin: [
    {
      txid: ZEROS,
      vout: MAX_VALUE,
      prevout: null,
      scriptsig: "03233708",
      scriptsig_asm: "OP_PUSHBYTES_3 233708",
    },
  ],
  vout: [
    {
      scriptpubkey: "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac",
      scriptpubkey_asm:
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 edf10a7fac6b32e24daa5305c723f3de58db1bc8 OP_EQUALVERIFY OP_CHECKSIG",
      scriptpubkey_type: "p2pkh",
      value: blockReward,
    },
    {
      //op return push 36 bytes 4 btyes commitment + hash256 of witness merkle root + zeros
      scriptpubkey: "6a24aa21a9ed", // add the witness commitment later
      scriptpubkey_type: "op_return",
      value: 0,
    },
  ],
} as unknown as Transaction;

export const generateCoinbaseTransaction = (
  totalFee: number,
  commitmentHeader: string
) => {
  coinbaseTemplate.vout[1].scriptpubkey = `6a24aa21a9ed${commitmentHeader}`;
  coinbaseTemplate.vout[0].value = blockReward + totalFee;

  return coinbaseTemplate;
};
