import { reversify, sha256 } from "../../utils";
import { Transaction } from "../../types";
import { merkleRoot } from "./merkleRoot";
import { txSerializer } from "../encoding/serializer";
import { ZEROS, generateCoinbaseTransaction } from "./coinbaseTransaction";
import { totalFee } from "./fee";
import { isClassStaticBlockDeclaration } from "typescript";

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

  const prevBlockHeader =
    "0000000000000000000000000000000000000000000000000000000000000000"; //1 greater than the difficulty

  const witnessMerkleRootHash = reversify(
    merkleRoot([
      ZEROS, //zeros are for the coinbase transaction
      ...txs.map((tx) =>
        reversify(sha256(sha256(txSerializer(tx).serializedWTx)))
      ),
    ])
  );
  const commitmentHash = sha256(sha256(witnessMerkleRootHash + ZEROS));
  const fees = totalFee(txs);
  const coinbaseTransaction = generateCoinbaseTransaction(fees, commitmentHash);

  const prevBlockHash = reversify(sha256(sha256(prevBlockHeader)));
  const merkleRootHash = reversify(
    merkleRoot(
      [coinbaseTransaction, ...txs].map((tx) =>
        reversify(sha256(sha256(txSerializer(tx).serializedTx)))
      )
    )
  );

  const time = Buffer.alloc(4);
  time.writeUint32LE(Math.floor(Date.now() / 1000));
  const nbits = "1f00ffff";

  for (let nonce = 0; nonce < 0xffffffff; nonce++) {
    const nonceBuf = Buffer.alloc(4);
    nonceBuf.writeUInt32LE(nonce);
    const serializedBlock = `${version.toString(
      "hex"
    )}${prevBlockHash}${merkleRootHash}${time.toString(
      "hex"
    )}${nbits}${nonceBuf.toString("hex")}`;

    // console.log(serializedBlock);
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
