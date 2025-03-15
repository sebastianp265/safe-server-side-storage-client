import { gcm } from "@noble/ciphers/aes";
import { concatBytes } from "@noble/ciphers/utils";
import { cryptoAssert, random } from "./utils";

export const NONCE_LENGTH = 12;

export function encryptWithRandomNonce(
    key: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
) {
    const nonce = random(NONCE_LENGTH);
    return encrypt(key, nonce, aad, plaintext);
}

export function encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
) {
    cryptoAssert(nonce.length === NONCE_LENGTH);
    return concatBytes(nonce, gcm(key, nonce, aad).encrypt(plaintext));
}

export function decrypt(
    key: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array,
) {
    const nonce = ciphertext.subarray(0, NONCE_LENGTH);
    return gcm(key, nonce, aad).decrypt(ciphertext.subarray(NONCE_LENGTH));
}
