// Tiny key-value store in IndexedDB. Opened only by the background: content scripts can read
// chrome.storage, but not an extension-origin database, so the pairing key lives here.
const STORE = "kv";

function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("keyorra", 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run<T>(mode: IDBTransactionMode, op: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const d = await db();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = d.transaction(STORE, mode);
      const req = op(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    d.close();
  }
}

export const idbGet = async <T>(key: string): Promise<T | null> => ((await run("readonly", (s) => s.get(key))) as T | undefined) ?? null;
export const idbPut = (key: string, value: unknown): Promise<unknown> => run("readwrite", (s) => s.put(value, key));
export const idbDelete = (key: string): Promise<unknown> => run("readwrite", (s) => s.delete(key));
