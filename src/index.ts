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

(async () => {
    const files = fs.readdirSync("./mempool");
    const outputFile = path.join(__dirname, "..", "output.txt");
    let mempool: Transaction[] = [];

    const blockSize = 4 * 1e6;

    for (const file of files) {
        // const tx = JSON.parse(fs.readFileSync(`./mempool/${file}`, "utf8")) as Tx;
        const tx = {
            version: 1,
            locktime: 0,
            vin: [
                {
                    txid: "f3898029a8699bd8b71dc6f20e7ec2762a945a30d6a9f18034ce92a9d6cdd26c",
                    vout: 1,
                    prevout: {
                        scriptpubkey:
                            "00144639af50cc9b5fcc4fc09644c0140078b2d2356c",
                        scriptpubkey_asm:
                            "OP_0 OP_PUSHBYTES_20 4639af50cc9b5fcc4fc09644c0140078b2d2356c",
                        scriptpubkey_type: "v0_p2wpkh",
                        scriptpubkey_address:
                            "bc1qgcu675xvnd0ucn7qjezvq9qq0zedydtv07pqxg",
                        value: 338586,
                    },
                    scriptsig: "",
                    scriptsig_asm: "",
                    witness: [
                        "30450221008f05cd9bc6679ad3b1e5316370a71779d587d9ff9ceaebb9dfa97288e6abf7fb02203951f6ea925965c7719039984929bac73e7934c86237dc40d72459a694f378ec01",
                        "02bb0543170d1752bfb0d173724effdc58a708c53d5154e56364e6cb19fd993a73",
                    ],
                    is_coinbase: false,
                    sequence: 4294967293,
                },
            ],
            vout: [
                {
                    scriptpubkey:
                        "5120b09182bc1fc70f752d4d885ec8e68156325b75881de16bb1b5d3e3bf53ff01fd",
                    scriptpubkey_asm:
                        "OP_PUSHNUM_1 OP_PUSHBYTES_32 b09182bc1fc70f752d4d885ec8e68156325b75881de16bb1b5d3e3bf53ff01fd",
                    scriptpubkey_type: "v1_p2tr",
                    scriptpubkey_address:
                        "bc1pkzgc90qlcu8h2t2d3p0v3e5p2ce9kavgrhskhvd4603m75llq87s2eyxqn",
                    value: 2576,
                },
                {
                    scriptpubkey:
                        "00144639af50cc9b5fcc4fc09644c0140078b2d2356c",
                    scriptpubkey_asm:
                        "OP_0 OP_PUSHBYTES_20 4639af50cc9b5fcc4fc09644c0140078b2d2356c",
                    scriptpubkey_type: "v0_p2wpkh",
                    scriptpubkey_address:
                        "bc1qgcu675xvnd0ucn7qjezvq9qq0zedydtv07pqxg",
                    value: 333840,
                },
            ],
        };

        // mempool.set(`${file}`.split(".")[0], {
        //   ...tx,
        //   txid: `${file}`.split(".")[0],
        // });
        const transaction = new Transaction(tx.version, tx.locktime);
        for (const input of tx.vin) {
            transaction.addInput(new Input(input));
        }

        for (const output of tx.vout) {
            transaction.addOutput(new Output(output));
        }
        mempool.push(transaction);
        break;
    }

    for (const tx of mempool) {
        signatureValidator(tx);
    }

    // let txs = [];
    // mempool.sort((txA, txB) => feePerByte(txB) - feePerByte(txA));
    // let blockWeight = 0;
    // for (const tx of mempool) {
    //     if (tx.weight + blockWeight > blockSize) break;

    //     txs.push(tx);
    //     blockWeight += tx.weight;
    // }

    // try {
    //     fs.unlinkSync(outputFile);
    // } catch (err) {}
    // const { serializedBlock, blockHash, coinbaseTransaction } = mine(txs);

    // fs.writeFileSync(outputFile, serializedBlock);
    // fs.appendFileSync(outputFile, "\n");
    // fs.appendFileSync(outputFile, coinbaseTransaction.serializedWTx);
    // fs.appendFileSync(outputFile, "\n");
    // fs.appendFileSync(outputFile, coinbaseTransaction.txid);
    // fs.appendFileSync(outputFile, "\n");
    // for (const tx of txs) {
    //     fs.appendFileSync(outputFile, tx.txid);
    //     fs.appendFileSync(outputFile, "\n");
    // }
    // console.log(fs.readFileSync(outputFile, "utf8").split("\n").length);
})();
