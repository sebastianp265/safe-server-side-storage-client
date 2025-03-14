import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";

export function mac(data: Uint8Array, key: Uint8Array): Uint8Array {
    return hmac(sha256, key, data);
}
