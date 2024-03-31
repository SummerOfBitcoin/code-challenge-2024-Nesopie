import { ScriptStack } from "./stack";

export class Script {
  static execute(script: string) {
    const stack = new ScriptStack();
    stack.execute(script);
  }
}
