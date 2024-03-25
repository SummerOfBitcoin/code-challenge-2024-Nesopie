import { IStore } from "../interfaces/store";
import { Transaction } from "../types";

class Mempool {
  map: Map<string, Transaction>;
  constructor() {
    this.map = new Map<string, Transaction>();
  }
  get(key: string): Transaction | undefined {
    return this.map.get(key);
  }
  set(key: string, value: Transaction): void {
    this.map.set(key, value);
  }
}

export const mempool = new Mempool();
