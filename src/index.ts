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
  let txs: Transaction[] = [];

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
    txs.push(transaction);
  }

  let validTxs = [];

  for (const tx of txs) {
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

  //<txid + vout, txid of the spending tx>
  const spentOutputs = new Map<string, string>();
  const mempool = new Map<string, Transaction>();

  outer: for (const tx of validTxs) {
    for (const input of tx.vin) {
      if (spentOutputs.has(input.txid + input.vout)) {
        //check if it has rbf enabled
        if (tx.isBip125Replaceable) {
          mempool.delete(tx.txid);
        } else continue outer; //if it is not replaceable then it is not valid. The tx has already been confirmed and txs that spend the same input are ignored
      }
      spentOutputs.set(input.txid + input.vout, tx.txid);
    }
    mempool.set(tx.txid, tx);
  }

  txs = [];
  const mempoolTxIds = new Set<string>(spentOutputs.values());
  for (const txid of mempoolTxIds) {
    const tx = mempool.get(txid);
    if (tx) txs.push(tx);
  }

  let confirmedTxs = [];

  txs.sort((txA, txB) => feePerByte(txB) - feePerByte(txA));
  let blockWeight = 0;
  for (const tx of txs) {
    if (tx.weight + blockWeight > blockSize) break;

    confirmedTxs.push(tx);
    blockWeight += tx.weight;
  }

  try {
    fs.unlinkSync(outputFile);
  } catch (err) {}
  const { serializedBlock, blockHash, coinbaseTransaction } =
    mine(confirmedTxs);

  fs.writeFileSync(outputFile, serializedBlock);
  fs.appendFileSync(outputFile, "\n");
  fs.appendFileSync(outputFile, coinbaseTransaction.serializedWTx);
  fs.appendFileSync(outputFile, "\n");
  fs.appendFileSync(outputFile, coinbaseTransaction.txid);
  fs.appendFileSync(outputFile, "\n");
  for (const tx of confirmedTxs) {
    fs.appendFileSync(outputFile, tx.txid);
    fs.appendFileSync(outputFile, "\n");
  }
  console.log(fs.readFileSync(outputFile, "utf8").split("\n").length);
})();
