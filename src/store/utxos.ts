import { Transaction } from "../types";

class UTXOs {
  map: Map<string, Set<string>>;
  constructor() {
    this.map = new Map<string, Set<string>>();
  }
  private get(key: string): Set<string> | undefined {
    return this.map.get(key);
  }
  private set(key: string, value?: string): void {
    if (!this.map.has(key)) {
      this.map.set(key, new Set<string>());
    }
    if (value) this.map.set(key, this.map.get(key)!.add(value));
  }

  getUTXOs() {
    //get all the keys and check if it's size is 1 and that element is empty
    const utxos: Set<string> = new Set<string>();
    for (const key of this.map.keys()) {
      if (this.map.get(key)!.size === 0) {
        utxos.add(key);
      }
    }
    return utxos;
  }

  isInputSpent(txid: string, vout: number): boolean {
    const spentBy = this.get(txid + vout);
    if (!spentBy) return false;
    return spentBy.size > 0;
  }

  doesUTXOExist(txid: string, vout: number): boolean {
    return this.get(txid + vout) !== undefined;
  }

  addUTXOs(tx: Transaction): void {
    for (const input of tx.vin) {
      this.set(input.txid + input.vout, tx.txid);
    }

    for (let i = 0; i < tx.vout.length; i++) {
      this.set(tx.txid + i);
    }
  }
}

export const utxos = new UTXOs();
