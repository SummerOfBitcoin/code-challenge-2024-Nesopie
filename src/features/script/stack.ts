import { IStack } from "../../interfaces/store";

export class Stack<T> implements IStack<T> {
  private stack: T[] = [];

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
  private scriptSigAsm: string;
  private scriptPubKeyAsm: string;
  private executionStates: boolean[] = [true];

  constructor(scriptSigAsm: string, scriptPubKeyAsm: string) {
    super();
    this.scriptSigAsm = scriptSigAsm;
    this.scriptPubKeyAsm = scriptPubKeyAsm;
  }

  //load the scriptSigAsm into the stack as the input
  initializeStack(): void {
    if (this.scriptSigAsm) {
      const scriptTokens = this.scriptSigAsm.split(" ");
    }
  }

  shouldExecute(): boolean {
    return this.executionStates[this.executionStates.length - 1];
  }

  onIf(condition: boolean) {
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
