const store = new Map<string, unknown>();
export const cache = {
  get: (k: string) => store.get(k),
  set: (k: string, v: unknown) => void store.set(k, v),
};
