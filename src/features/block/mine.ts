import { reversify, sha256 } from "../../utils";
import { Transaction } from "../transaction";
import { merkleRoot } from "./merkleRoot";
import { generateCoinbaseTransaction } from "./coinbaseTransaction";
import { totalFee } from "./fee";
import { DIFFICULTY, WITNESS_RESERVED_VALUE } from "../../constants";

export const mine = (
  txs: Transaction[]
): {
  serializedBlock: string;
  blockHash: string;
  coinbaseTransaction: Transaction;
} => {
  const difficulty =
    "0000ffff00000000000000000000000000000000000000000000000000000000";
  const version = Buffer.alloc(4);
  version.writeInt32LE(4);

  // const witnessMerkleRootHash = merkleRoot([
  //   ZEROS, //zeros are for the coinbase transaction
  //   ...txs.map((tx) => sha256(sha256(txSerializer(tx).serializedWTx))),
  // ]);
  const witnessMerkleRootHash = merkleRoot([
    WITNESS_RESERVED_VALUE,
    ...txs.map((tx) => reversify(tx.wtxid)),
  ]);
  const commitmentHash = sha256(
    sha256(witnessMerkleRootHash + WITNESS_RESERVED_VALUE)
  );
  const fees = totalFee(txs);
  const coinbaseTransaction = generateCoinbaseTransaction(fees, commitmentHash);

  const prevBlockHash = DIFFICULTY; //make it the same as the difficulty

  const merkleRootHash = merkleRoot(
    [coinbaseTransaction, ...txs].map((tx) => reversify(tx.txid))
  );

  const time = Buffer.alloc(4);
  time.writeUint32LE(Math.floor(Date.now() / 1000));
  // const nbits = "1f00ffff";
  const nbits = Buffer.alloc(4);
  nbits.writeUint32LE(0x1f00ffff);

  for (let nonce = 0; nonce < 0xffffffff; nonce++) {
    const nonceBuf = Buffer.alloc(4);
    nonceBuf.writeUInt32LE(nonce);
    const serializedBlock = `${version.toString(
      "hex"
    )}${prevBlockHash}${merkleRootHash}${time.toString("hex")}${nbits.toString(
      "hex"
    )}${nonceBuf.toString("hex")}`;

    const blockHash = reversify(sha256(sha256(serializedBlock)));
    if (
      Buffer.from(difficulty, "hex").compare(Buffer.from(blockHash, "hex")) < 0
    )
      continue;
    return { serializedBlock, blockHash, coinbaseTransaction };
  }

  return {
    serializedBlock: "",
    blockHash: "",
    coinbaseTransaction: {
      version: 0,
      locktime: 0,
      vin: [],
      vout: [],
    } as unknown as Transaction,
  };
};
