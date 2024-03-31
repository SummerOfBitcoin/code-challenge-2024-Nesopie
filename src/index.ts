import * as fs from "fs";
// import { mempool } from "./store/mempool";
import { utxos } from "./store/utxos";
import { LengthValidator } from "./features/validator/length";
import { HashValidator } from "./features/validator/hash";
import { reversify, sha256 } from "./utils";
import { feePerByte } from "./features/block/fee";
import { mine } from "./features/block/mine";
import * as path from "path";
import { signatureValidator } from "./features/validator/signature";
import { Input, Output, Transaction, Tx } from "./features/transaction";
import { Transaction as BitcoinTx } from "bitcoinjs-lib";
import { ScriptValidator } from "./features/validator/script";
import { collapseTextChangeRangesAcrossMultipleVersions } from "typescript";

(async () => {
  const files = fs.readdirSync("./mempool");
  const outputFile = path.join(__dirname, "..", "output.txt");
  let mempool: Transaction[] = [];

  const blockSize = 4 * 1e6;

  for (const file of files) {
    const tx = JSON.parse(fs.readFileSync(`./mempool/${file}`, "utf8"));

    const transaction = new Transaction(tx.version, tx.locktime);
    for (const input of tx.vin) {
      transaction.addInput(new Input(input));
    }

    for (const output of tx.vout) {
      transaction.addOutput(new Output(output));
    }
    mempool.push(transaction);
  }

  let validTxs = [];

  for (const tx of mempool) {
    if (
      !ScriptValidator(tx) ||
      !LengthValidator(tx) ||
      !HashValidator(tx) ||
      !signatureValidator(tx)
    ) {
      console.log(tx);
      continue;
    }
    validTxs.push(tx);
  }

  const txs = [];

  validTxs.sort((txA, txB) => feePerByte(txB) - feePerByte(txA));
  let blockWeight = 0;
  for (const tx of validTxs) {
    if (tx.weight + blockWeight > blockSize) break;

    txs.push(tx);
    blockWeight += tx.weight;
  }

  try {
    fs.unlinkSync(outputFile);
  } catch (err) {}
  const { serializedBlock, blockHash, coinbaseTransaction } = mine(txs);

  fs.writeFileSync(outputFile, serializedBlock);
  fs.appendFileSync(outputFile, "\n");
  fs.appendFileSync(outputFile, coinbaseTransaction.serializedWTx);
  fs.appendFileSync(outputFile, "\n");
  fs.appendFileSync(outputFile, coinbaseTransaction.txid);
  fs.appendFileSync(outputFile, "\n");
  for (const tx of txs) {
    fs.appendFileSync(outputFile, tx.txid);
    fs.appendFileSync(outputFile, "\n");
  }
  console.log(fs.readFileSync(outputFile, "utf8").split("\n").length);
})();
