export async function deriveKeyFromPassphrase(passphrase, roomId) {
  const enc = new TextEncoder();
  const salt = enc.encode("salt:"+roomId);
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations:150000, hash:"SHA-256" },
    baseKey,
    { name:"AES-GCM", length:256 },
    false,
    ["encrypt","decrypt"]
  );
}
export async function encryptText(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, new TextEncoder().encode(text));
  return { iv, ciphertext:new Uint8Array(ciphertext) };
}
export async function decryptText(key, ivBuf, cipherBuf) {
  const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv:new Uint8Array(ivBuf) }, key, new Uint8Array(cipherBuf));
  return new TextDecoder().decode(pt);
}
// conversions
export function bufToBase64(buf){
  let s=""; const b=new Uint8Array(buf); for(let i=0;i<b.byteLength;i++) s+=String.fromCharCode(b[i]); return btoa(s);
}
export function base64ToUint8(b64){
  const s=atob(b64); const a=new Uint8Array(s.length); for(let i=0;i<s.length;i++) a[i]=s.charCodeAt(i); return a;
}
// For sending to Supabase bytea (ArrayBuffer via Uint8Array)
export function base64ToBuf(b64){ return base64ToUint8(b64); }
