export interface IStore<K, V> {
  get(key: K): V | undefined;
  set(key: K, value: V): void;
}

export interface IStack<K> {
  push(key: K): void;
  pop(): K | undefined;
}
