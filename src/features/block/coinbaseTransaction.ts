// import { Transaction } from "../../types";
import { MAX_VALUE, WITNESS_RESERVED_VALUE } from "../../constants";
import { compactSize } from "../encoding/compactSize";
import { Input, Output, Transaction } from "../transaction";

// export const ZEROS =
//   "0000000000000000000000000000000000000000000000000000000000000000";
// const MAX_VALUE = 0xffffffff;
// const height = 538403;
const blockReward = 1250000000;

export const generateCoinbaseTransaction = (
  totalFee: number,
  commitmentHeader: string
) => {
  const transaction = new Transaction(0, 0);
  const input = new Input({
    txid: WITNESS_RESERVED_VALUE,
    vout: MAX_VALUE,
    prevout: null,
    scriptsig: "03233708", //block number is 233708
    scriptsig_asm: "OP_PUSHBYTES_3 233708",
    witness: [WITNESS_RESERVED_VALUE],
    sequence: 0,
    is_coinbase: true,
  });

  const output1 = new Output({
    scriptpubkey: "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac",
    scriptpubkey_asm:
      "OP_DUP OP_HASH160 OP_PUSHBYTES_20 edf10a7fac6b32e24daa5305c723f3de58db1bc8 OP_EQUALVERIFY OP_CHECKSIG",
    scriptpubkey_type: "p2pkh",
    value: blockReward + totalFee,
  });

  const output2 = new Output({
    scriptpubkey: "6a24aa21a9ed" + commitmentHeader,
    scriptpubkey_asm: "OP_RETURN OP_PUSHBYTES_36 aa21a9ed" + commitmentHeader,
    scriptpubkey_type: "op_return",
    value: 0,
  });

  transaction.addInput(input);
  transaction.addOutput(output1);
  transaction.addOutput(output2);

  return transaction;
};
