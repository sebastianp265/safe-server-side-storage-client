import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";

export const KEY_LENGTH_BYTES = sha256.outputLen;

export function kdfOneKey(
    ikm: Uint8Array,
    salt: Uint8Array | null,
    info: Uint8Array,
    key_length: number = KEY_LENGTH_BYTES,
) {
    return hkdfSHA256(ikm, salt, info, key_length);
}

export function kdfTwoKeys(
    ikm: Uint8Array,
    salt: Uint8Array | null,
    info: Uint8Array,
    first_key_length: number = KEY_LENGTH_BYTES,
    second_key_length: number = KEY_LENGTH_BYTES,
) {
    const full_key = hkdfSHA256(
        ikm,
        salt,
        info,
        first_key_length + second_key_length,
    );
    return [
        full_key.subarray(0, first_key_length),
        full_key.subarray(first_key_length),
    ] as const;
}

function hkdfSHA256(
    ikm: Uint8Array,
    salt: Uint8Array | null,
    info: Uint8Array,
    keyLength: number,
): Uint8Array {
    return hkdf(sha256, ikm, salt, info, keyLength);
}
