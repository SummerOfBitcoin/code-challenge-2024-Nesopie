import { Input } from "./input";
import { Output } from "./output";
import { Serializer } from "../../encoding/serializer";
import { hash160, hash256, reversify, sha256 } from "../../../utils";
import { SigHash, TransactionType } from "../../../types";
import cloneDeep from "lodash.clonedeep";
import { Errors } from "../errors";
import { calculateWeight } from "../utils";
import { ZERO } from "../../../constants";
import { TEMPLATES } from "../../encoding/witnessTemplates";
import { compactSize } from "../../encoding/compactSize";
import {
  collapseTextChangeRangesAcrossMultipleVersions,
  getTsBuildInfoEmitOutputFilePath,
} from "typescript";

//depending on static serializer methods, instead use dependency injection
export class Transaction {
  private _txid: string | undefined; //cache these values
  private _wtxid: string | undefined;
  private _serializedTx: string | undefined;
  private _serializedWTx: string | undefined;
  private _weight: number | undefined;
  private _hashPrevouts: string | undefined;
  private _hashSequence: string | undefined;
  private _hashOutputs: string | undefined;

  version: number;
  locktime: number;
  vin: Input[] = [];
  vout: Output[] = [];
  isSegwit = false;
  isBip125Replaceable = false;

  constructor(version: number, locktime: number) {
    this.version = version;
    this.locktime = locktime;
  }

  addInput(input: Input) {
    this.resetState();
    if (input.witness && input.witness.length > 0) this.isSegwit = true;
    if (input.sequence < 0xffffffff - 1) this.isBip125Replaceable = true;
    this.vin.push(input);
  }

  addOutput(output: Output) {
    this.resetState();
    this.vout.push(output);
  }

  signWith(
    inputIndex: number,
    sighash: SigHash,
    transactionType: TransactionType,
    extFlag: number = 0x00,
    extension?: string
  ) {
    if (
      transactionType === TransactionType.P2PKH ||
      transactionType === TransactionType.P2SH
    ) {
      const txCopy = cloneDeep(this);
      let hashcode = Buffer.alloc(4);
      switch (sighash) {
        case SigHash.ALL:
          for (let i = 0; i < txCopy.vin.length; i++) {
            hashcode.writeUint32LE(1, 0);
            if (i === inputIndex) {
              const input = txCopy.vin[i].prevout;
              if (!input) throw new Error(Errors.INVALID_INPUT);
              txCopy.vin[i].scriptsig = input.scriptpubkey;
            } else {
              txCopy.vin[i].scriptsig = "";
            }
          }
          break;
        case SigHash.ALL | SigHash.ANYONE_CAN_PAY:
          hashcode.writeUint32LE(0x81, 0);
          txCopy.vin = [txCopy.vin[inputIndex]];
          const input = txCopy.vin[0].prevout;
          if (!input) throw new Error(Errors.INVALID_INPUT);
          txCopy.vin[0].scriptsig = input.scriptpubkey;
          break;
      }

      return txCopy.serializedTx + hashcode.toString("hex");
    } else if (transactionType === TransactionType.P2TR) {
      let serializedWTx = "";
      const hashtype = Buffer.alloc(1);
      hashtype.writeUint32LE(sighash, 0);

      const nVersion = Buffer.alloc(4);
      nVersion.writeUint32LE(this.version, 0);

      const nLocktime = Buffer.alloc(4);
      nLocktime.writeUint32LE(this.locktime, 0);

      let prevouts = "";
      let shaPrevouts = "";

      let amounts = "";
      let shaAmounts = "";

      let scripts = "";
      let shaScripts = "";

      let sequences = "";
      let shaSequences = "";

      let annex = undefined;

      if (tx.vin[inputIndex].witness && tx.vin[inputIndex].witness.length > 1) {
        const input = tx.vin[inputIndex];
        const lastWitness = input.witness[input.witness.length - 1];

        if (lastWitness.startsWith("50")) annex = lastWitness;
      }
      const annexBit = Buffer.alloc(1);
      annexBit.writeUint8(annex ? 1 : 0, 0);

      const extendBit = Buffer.alloc(1);
      extendBit.writeUint8(extension ? 1 : 0, 0);

      const spendType = Buffer.alloc(1);
      spendType.writeUint8(
        (extFlag + extendBit.readUint8(0)) * 2 + annexBit.readUint8(0)
      );

      if ((sighash & SigHash.ANYONE_CAN_PAY) === SigHash.ANYONE_CAN_PAY) {
        for (const input of this.vin) {
          prevouts += reversify(input.txid);
          const prevoutVout = Buffer.alloc(4);
          prevoutVout.writeUint32LE(input.vout, 0);
          prevouts += prevoutVout.toString("hex");

          if (!input.prevout) continue;

          const amount = Buffer.alloc(8);
          amount.writeBigInt64LE(BigInt(input.prevout!.value), 0);
          amounts += amount.toString("hex");

          scripts += input.prevout?.scriptpubkey;

          const sequence = Buffer.alloc(4);
          sequence.writeUint32LE(input.sequence, 0);
          sequences += sequence.toString("hex");
        }
      }

      shaPrevouts = hash256(prevouts);
      shaAmounts = hash256(amounts);
      shaScripts = hash256(scripts);
      shaSequences = hash256(sequences);

      let outputs = "";
      let shaOutputs = "";

      if ((sighash & 0x03) < 2 || (sighash & 0x02) > 3) {
        for (const output of this.vout) {
          const amount = Buffer.alloc(8);
          amount.writeBigInt64LE(BigInt(output.value), 0);
          outputs += amount.toString("hex") + output.scriptpubkey;
        }

        shaOutputs = hash256(outputs);
      }

      let inputData = "";
      if ((sighash & SigHash.ANYONE_CAN_PAY) === SigHash.ANYONE_CAN_PAY) {
        const input = this.vin[inputIndex];

        inputData += reversify(input.txid);

        const prevoutVout = Buffer.alloc(4);
        prevoutVout.writeUint32LE(input.vout, 0);
        inputData += prevoutVout.toString("hex");

        const amount = Buffer.alloc(8);
        amount.writeBigInt64LE(BigInt(input.prevout!.value), 0);
        inputData += amount.toString("hex");

        inputData += input.prevout!.scriptpubkey;

        const sequence = Buffer.alloc(4);
        sequence.writeUint32LE(input.sequence, 0);
        inputData += sequence.toString("hex");
      } else {
        const index = Buffer.alloc(4);
        index.writeUint32LE(inputIndex, 0);

        inputData += index.toString("hex");
      }

      let outputData = "";
      let shaoutputData = "";
      if ((sighash & 0x03) === SigHash.SINGLE) {
        const amount = Buffer.alloc(8);
        amount.writeBigInt64LE(BigInt(this.vout[inputIndex].value), 0);

        outputData +=
          amount.toString("hex") + this.vout[inputIndex].scriptpubkey;
        shaoutputData = hash256(outputData);
      }
    }
    let serializedWTx = "";

    const version = Buffer.alloc(4);
    version.writeUint32LE(this.version, 0);

    let prevouts = "";
    let sequences = "";
    let hashPrevouts = "";
    let hashSequence = "";
    if (sighash >= SigHash.ANYONE_CAN_PAY) hashPrevouts = ZERO;
    else {
      if (this._hashPrevouts) {
        hashPrevouts = this._hashPrevouts;
      } else {
        for (const input of this.vin) {
          prevouts += reversify(input.txid);
          const prevoutVout = Buffer.alloc(4);
          prevoutVout.writeUint32LE(input.vout, 0);
          prevouts += prevoutVout.toString("hex");
        }
        hashPrevouts = hash256(prevouts);
        this._hashPrevouts = hashPrevouts;
      }
    }

    if (
      sighash >= SigHash.ANYONE_CAN_PAY ||
      sighash === SigHash.SINGLE ||
      sighash === SigHash.NONE
    )
      hashSequence = ZERO;
    else {
      if (this._hashSequence) {
        hashSequence = this._hashSequence;
      } else {
        for (const input of this.vin) {
          const sequence = Buffer.alloc(4);
          sequence.writeUint32LE(input.sequence, 0);
          sequences += sequence.toString("hex");
        }
        hashSequence = hash256(sequences);
        this._hashSequence = hashSequence;
      }
    }

    let outputs = "";
    let hashOutputs = "";
    if (
      (sighash & 0x1f) === SigHash.SINGLE ||
      (sighash & 0x1f) === SigHash.NONE
    ) {
      if (
        (sighash & 0x1f) === SigHash.SINGLE &&
        inputIndex < this.vout.length
      ) {
        hashOutputs = hash256(this.vout[inputIndex].serialize());
      } else hashOutputs = ZERO;
    } else {
      if (this._hashOutputs) {
        hashOutputs = this._hashOutputs;
      } else {
        for (const output of this.vout) {
          outputs += output.serialize();
        }
        hashOutputs = hash256(outputs);
        this._hashOutputs = hashOutputs;
      }
    }

    const input = this.vin[inputIndex];
    if (!input) throw new Error(Errors.INVALID_VOUT);
    const vout = Buffer.alloc(4);
    vout.writeUint32LE(input.vout, 0);
    const outpoint = reversify(input.txid) + vout.toString("hex");

    if (!input.witness) throw new Error(Errors.INVALID_WITNESS);
    let scriptCode = "";
    if (transactionType === TransactionType.P2WPKH) {
      if (!input.witness[1]) throw new Error(Errors.PUBKEY_NOT_FOUND);
      scriptCode = TEMPLATES.P2WPKH(hash160(input.witness[1]));
    } else {
      const script = input.witness[input.witness.length - 1];
      const scriptLength = compactSize(BigInt(script.length / 2));
      scriptCode = scriptLength.toString("hex") + script;
    }

    if (!input.prevout) throw new Error(Errors.INVALID_PREVOUT);
    const amount = Buffer.alloc(8);
    amount.writeBigInt64LE(BigInt(input.prevout.value), 0);

    const nSequence = Buffer.alloc(4);
    nSequence.writeUint32LE(input.sequence, 0);

    const nLocktime = Buffer.alloc(4);
    nLocktime.writeUint32LE(this.locktime, 0);

    const hashcode = Buffer.alloc(4);
    hashcode.writeUint32LE(sighash, 0);

    serializedWTx += version.toString("hex");
    serializedWTx += hashPrevouts;
    serializedWTx += hashSequence;
    serializedWTx += outpoint;
    serializedWTx += scriptCode;
    serializedWTx += amount.toString("hex");
    serializedWTx += nSequence.toString("hex");
    serializedWTx += hashOutputs;
    serializedWTx += nLocktime.toString("hex");
    serializedWTx += hashcode.toString("hex");

    return serializedWTx;
  }

  get serializedTx() {
    if (this._serializedTx) return this._serializedTx;
    this._serializedTx = Serializer.serializeTx(this);
    return this._serializedTx;
  }

  get serializedWTx() {
    if (this._serializedWTx) return this._serializedWTx;
    this._serializedWTx = Serializer.serializeWTx(this);
    return this._serializedWTx;
  }

  get txid() {
    if (this._txid) return this._txid;
    const txid = reversify(sha256(sha256(this.serializedTx)));
    this._txid = txid;
    return this._txid;
  }

  get wtxid() {
    if (!this.isSegwit) return this.txid;
    if (this._wtxid) return this._wtxid;
    const wtxid = reversify(sha256(sha256(this.serializedWTx)));
    this._wtxid = wtxid;
    return this._wtxid;
  }

  get weight() {
    if (this._weight) return this._weight;
    const weight = calculateWeight(this, this.isSegwit);
    this._weight = weight;
    return this._weight;
  }

  private resetState() {
    //remove cache as it gets invalidated when tx gets changed such as when you're adding input or outputs;
    this._txid = undefined;
    this._wtxid = undefined;
    this._serializedTx = undefined;
    this._serializedWTx = undefined;
  }
}

const tx = {
  version: 2,
  locktime: 0,
  vin: [
    {
      txid: "5e6197dbc25abd3a9b2af9a8e55458a9b7b7a85c4a13cfdadb9e187ce9334588",
      vout: 3,
      prevout: {
        scriptpubkey:
          "51206738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
        scriptpubkey_asm:
          "OP_PUSHNUM_1 OP_PUSHBYTES_32 6738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
        scriptpubkey_type: "v1_p2tr",
        scriptpubkey_address:
          "bc1pvuud29rama7c6aehhm49v90xxsuuce6e8pgcpkdj400zzews0vfqfs2xvd",
        value: 600,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "42a0928529ab59bfc67993eb2cfb1d72911fed3e8de4c560c2eab4a001cebb214401dadd2c0493efc5bdc024e9294d17dd3734cb6fc0410550da4a04186abdc4",
      ],
      is_coinbase: false,
      sequence: 4294967295,
    },
    {
      txid: "f9f2067be86bf9a33b82c50bfee830047811d24f94c719a3c3e5285f210f086f",
      vout: 5,
      prevout: {
        scriptpubkey:
          "51206738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
        scriptpubkey_asm:
          "OP_PUSHNUM_1 OP_PUSHBYTES_32 6738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
        scriptpubkey_type: "v1_p2tr",
        scriptpubkey_address:
          "bc1pvuud29rama7c6aehhm49v90xxsuuce6e8pgcpkdj400zzews0vfqfs2xvd",
        value: 600,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "b9d19c7160d923eec314c51881957fa6027da28b46cf835fed08dc80dbe94066263d962e882e43d63294ca0da9f1f26607b9693d3680f1d01352ddbcbf948828",
      ],
      is_coinbase: false,
      sequence: 4294967295,
    },
    {
      txid: "c89998a53471308b40f778325b8bd11eb78fa5b463138be2e9b9c793bd1e9c30",
      vout: 1,
      prevout: {
        scriptpubkey:
          "512025a6cb1be46f9b558e86f62db73cf12dcb883450b513669c72b1799be3d719e5",
        scriptpubkey_asm:
          "OP_PUSHNUM_1 OP_PUSHBYTES_32 25a6cb1be46f9b558e86f62db73cf12dcb883450b513669c72b1799be3d719e5",
        scriptpubkey_type: "v1_p2tr",
        scriptpubkey_address:
          "bc1pyknvkxlyd7d4tr5x7ckmw0839h9csdzsk5fkd8rjk9uehc7hr8jspctyvw",
        value: 1521924,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "612df80a166f44d3e17eef77386a8c95fa04535bb8b104ea0219f5406a5cfe826ecb9bea8b101de713df12dd46f103ddd5042ad041627868fa51c93b1f576f2683",
      ],
      is_coinbase: false,
      sequence: 4294967295,
    },
    {
      txid: "dfa57658052ba62cf2940160c6254e9b09dc6b66c7c0ceb27e1fb3335697b213",
      vout: 0,
      prevout: {
        scriptpubkey:
          "51206738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
        scriptpubkey_asm:
          "OP_PUSHNUM_1 OP_PUSHBYTES_32 6738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
        scriptpubkey_type: "v1_p2tr",
        scriptpubkey_address:
          "bc1pvuud29rama7c6aehhm49v90xxsuuce6e8pgcpkdj400zzews0vfqfs2xvd",
        value: 1775944,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "d44b3705971bb00c4544096ec9317d51cf38c0fdcda0306827b2c1ca3745acde15bc592c1fdcff8d20eb23095ca5a4b4aef8b4ab87048cf558b22c6f1f179fbc",
      ],
      is_coinbase: false,
      sequence: 4294967295,
    },
    {
      txid: "46e8e365435112ea61d4a031524a70d0b0ed436d2add67a23bb759a755aba82f",
      vout: 2,
      prevout: {
        scriptpubkey:
          "51206738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
        scriptpubkey_asm:
          "OP_PUSHNUM_1 OP_PUSHBYTES_32 6738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
        scriptpubkey_type: "v1_p2tr",
        scriptpubkey_address:
          "bc1pvuud29rama7c6aehhm49v90xxsuuce6e8pgcpkdj400zzews0vfqfs2xvd",
        value: 418446,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "bf450894077142b659dcafbb0b39a54f7857179fa3391ce90170a52ba885cc87be04f3029000bc13aa0851dc7abdfc772efd2e434d7c360ad2d66e39c3fc4e8e",
      ],
      is_coinbase: false,
      sequence: 4294967295,
    },
  ],
  vout: [
    {
      scriptpubkey:
        "51206738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_asm:
        "OP_PUSHNUM_1 OP_PUSHBYTES_32 6738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_type: "v1_p2tr",
      scriptpubkey_address:
        "bc1pvuud29rama7c6aehhm49v90xxsuuce6e8pgcpkdj400zzews0vfqfs2xvd",
      value: 1200,
    },
    {
      scriptpubkey:
        "51206738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_asm:
        "OP_PUSHNUM_1 OP_PUSHBYTES_32 6738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_type: "v1_p2tr",
      scriptpubkey_address:
        "bc1pvuud29rama7c6aehhm49v90xxsuuce6e8pgcpkdj400zzews0vfqfs2xvd",
      value: 1521924,
    },
    {
      scriptpubkey: "0014392f28fde2dcf2cccbd05885e22d7b823fb2b5d9",
      scriptpubkey_asm:
        "OP_0 OP_PUSHBYTES_20 392f28fde2dcf2cccbd05885e22d7b823fb2b5d9",
      scriptpubkey_type: "v0_p2wpkh",
      scriptpubkey_address: "bc1q8yhj3l0zmnevej7stzz7yttmsglm9dwehp26wh",
      value: 1824788,
    },
    {
      scriptpubkey: "a914ea6b832a05c6ca578baa3836f3f25553d41068a587",
      scriptpubkey_asm:
        "OP_HASH160 OP_PUSHBYTES_20 ea6b832a05c6ca578baa3836f3f25553d41068a5 OP_EQUAL",
      scriptpubkey_type: "p2sh",
      scriptpubkey_address: "3P4WqXDbSLRhzo2H6MT6YFbvBKBDPLbVtQ",
      value: 7609,
    },
    {
      scriptpubkey:
        "51206738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_asm:
        "OP_PUSHNUM_1 OP_PUSHBYTES_32 6738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_type: "v1_p2tr",
      scriptpubkey_address:
        "bc1pvuud29rama7c6aehhm49v90xxsuuce6e8pgcpkdj400zzews0vfqfs2xvd",
      value: 600,
    },
    {
      scriptpubkey:
        "51206738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_asm:
        "OP_PUSHNUM_1 OP_PUSHBYTES_32 6738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_type: "v1_p2tr",
      scriptpubkey_address:
        "bc1pvuud29rama7c6aehhm49v90xxsuuce6e8pgcpkdj400zzews0vfqfs2xvd",
      value: 600,
    },
    {
      scriptpubkey:
        "51206738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_asm:
        "OP_PUSHNUM_1 OP_PUSHBYTES_32 6738d5147ddf7d8d7737beea5615e63439cc6759385180d9b2abde2165d07b12",
      scriptpubkey_type: "v1_p2tr",
      scriptpubkey_address:
        "bc1pvuud29rama7c6aehhm49v90xxsuuce6e8pgcpkdj400zzews0vfqfs2xvd",
      value: 352123,
    },
  ],
};

const transaction = new Transaction(tx.version, tx.locktime);
for (const input of tx.vin) {
  transaction.addInput(new Input(input));
}

for (const output of tx.vout) {
  transaction.addOutput(new Output(output));
}
