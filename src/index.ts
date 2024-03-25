import * as fs from "fs";
import { Transaction } from "./types";
// import { mempool } from "./store/mempool";
import { utxos } from "./store/utxos";
import { LengthValidator } from "./features/validator/length";
import { HashValidator } from "./features/validator/hash";
import { reversify, sha256 } from "./utils";
import { txSerializer, txWeight } from "./features/encoding/serializer";
import { feePerByte } from "./features/block/fee";
import { mine } from "./features/block/mine";
import * as path from "path";

(async () => {
  const files = fs.readdirSync("./mempool");
  const outputFile = path.join(__dirname, "..", "output.txt");
  let mempool: Transaction[] = [];

  const blockSize = 2 * 1e6;

  for (const file of files) {
    const tx = JSON.parse(fs.readFileSync(`./mempool/${file}`, "utf8"));
    // mempool.set(`${file}`.split(".")[0], {
    //   ...tx,
    //   txid: `${file}`.split(".")[0],
    // });
    mempool.push(tx);
  }

  let txs = [];
  mempool.sort((txA, txB) => feePerByte(txB) - feePerByte(txA));
  let blockWeight = 0;
  for (const tx of mempool) {
    if (txWeight(tx) + blockWeight > blockSize) break;

    txs.push(tx);
    blockWeight += txWeight(tx);
  }

  const { serializedBlock, blockHash, coinbaseTransaction } = mine(txs);
  fs.writeFileSync(outputFile, serializedBlock);
  fs.appendFileSync(outputFile, "\n");
  fs.appendFileSync(outputFile, txSerializer(coinbaseTransaction).serializedTx);
  fs.appendFileSync(outputFile, "\n");
  for (const tx of txs) {
    fs.appendFileSync(
      outputFile,
      reversify(sha256(sha256(txSerializer(tx).serializedTx)))
    );
    fs.appendFileSync(outputFile, "\n");
  }
})();
