import * as bitcoin from "bitcoinjs-lib";

import { alice } from "./wallets.json";
import { text } from "stream/consumers";
import { reversify } from "../../utils";

const network = bitcoin.networks.regtest;

const redeemScript = bitcoin.script.compile([
  bitcoin.opcodes.OP_ADD,
  bitcoin.opcodes.OP_5,
  bitcoin.opcodes.OP_EQUAL,
]);
const p2sh = bitcoin.payments.p2sh({
  redeem: { output: redeemScript, network },
  network,
});

const transaction = new bitcoin.Transaction();
transaction.version = 2;
transaction.addInput(
  Buffer.from(
    reversify(
      "82f39b0d951d2a604568eabe47d6013a4d83dcf9c476c30c4d3ffafb72fbb21f"
    ),
    "hex"
  ),
  0
);

transaction.addOutput(
  bitcoin.address.toOutputScript(alice[1].p2wpkh!, network),
  5000
);

const sighash = bitcoin.Transaction.SIGHASH_ALL;

// transaction.hashForSignature();
