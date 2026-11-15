// Persistent state of the page: a key-value store on IndexedDB.
//
// IndexedDB rather than localStorage because it can hold CryptoKey
// objects: the channel keys stay non-extractable, the page can use them
// but never read them. Tapping a notification may reload the page, so
// nothing that matters lives in memory only.

const DB = 'clavix-approve';
const STORE = 'kv';

function request(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

let opening = null;

function database() {
  opening ??= new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return opening;
}

export async function get(key) {
  const db = await database();
  return request(db.transaction(STORE, 'readonly').objectStore(STORE).get(key));
}

export async function set(key, value) {
  const db = await database();
  return request(db.transaction(STORE, 'readwrite').objectStore(STORE).put(value, key));
}

export async function remove(key) {
  const db = await database();
  return request(db.transaction(STORE, 'readwrite').objectStore(STORE).delete(key));
}

export async function clear() {
  const db = await database();
  return request(db.transaction(STORE, 'readwrite').objectStore(STORE).clear());
}
