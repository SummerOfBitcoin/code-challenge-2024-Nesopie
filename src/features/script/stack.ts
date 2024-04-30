import { Transaction } from "../transaction";
import { IStack } from "../../interfaces/store";
import { executor } from "./executor";

export class Stack<T> implements IStack<T> {
  stack: T[] = [];

  push(key: T): void {
    this.stack.push(key);
  }

  pop(): T | undefined {
    return this.stack.pop();
  }

  top(): T | undefined {
    return this.stack[this.stack.length - 1];
  }
}

export class ScriptStack extends Stack<string> {
  private executionStates: boolean[] = [true];
  tx: Transaction;
  index: number;

  constructor(tx: Transaction, index: number) {
    super();
    this.tx = tx;
    this.index = index;
  }

  clear() {
    this.stack = [];
    this.executionStates = [true];
  }

  //load the scriptSigAsm into the stack as the input
  execute(scrpt: string): string {
    let script = `${scrpt}`; //copy the script
    while (script.length != 0) {
      const { script: newScript } = executor(this, script);
      script = newScript;
    }
    return this.top()!;
  }

  shouldExecute(): boolean {
    for (const state of this.executionStates) {
      if (!state) return false;
    }
    return true;
  }

  onIf(condition: boolean) {
    if (this.shouldExecute()) {
      this.stack.pop();
    }
    this.executionStates.push(condition);
  }

  onElse() {
    this.executionStates[this.executionStates.length - 1] =
      !this.executionStates[this.executionStates.length - 1];
  }

  onEndIf() {
    this.executionStates.pop();
  }
}
