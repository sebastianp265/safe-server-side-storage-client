import { describe, expect, test } from "vitest";
import { asciiStringToBytes, random } from "../../../utils";
import {
    decrypt,
    encryptWithRandomNonce,
} from "../../../authenticated-symmetric-encryption";

describe("authenticated symmetric encryption", () => {
    test("should get the same message after encryption and decryption with same keys and aad", async () => {
        const plaintext = asciiStringToBytes(
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit." +
                " Pellentesque a odio id mauris condimentum lacinia. Sed nibh nunc, pharetra in vestibulum vel," +
                " iaculis quis nulla. Vivamus maximus lorem dictum, blandit urna vitae, iaculis risus.",
        );
        const key = random(32);
        const aad = random(8);

        const ciphertext = encryptWithRandomNonce(key, aad, plaintext);
        const plaintext_after_decryption = decrypt(key, aad, ciphertext);

        expect(plaintext_after_decryption).toEqual(plaintext);
    });

    test("should throw error when different key is used", async () => {
        const plaintext = asciiStringToBytes(
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit." +
                " Pellentesque a odio id mauris condimentum lacinia. Sed nibh nunc, pharetra in vestibulum vel," +
                " iaculis quis nulla. Vivamus maximus lorem dictum, blandit urna vitae, iaculis risus.",
        );
        const key = random(32);
        const aad = random(8);

        const ciphertext = encryptWithRandomNonce(key, aad, plaintext);

        // Modify key
        key[key.length / 2] = ~key[key.length / 2];

        expect(() => decrypt(key, aad, ciphertext)).toThrowError(
            "aes/gcm: invalid ghash tag",
        );
    });

    test("should throw error when different aad is used", async () => {
        const plaintext = asciiStringToBytes(
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit." +
                " Pellentesque a odio id mauris condimentum lacinia. Sed nibh nunc, pharetra in vestibulum vel," +
                " iaculis quis nulla. Vivamus maximus lorem dictum, blandit urna vitae, iaculis risus.",
        );
        const key = random(32);
        const aad = random(8);

        const ciphertext = encryptWithRandomNonce(key, aad, plaintext);

        // Modify aad
        aad[3] = ~aad[3];

        expect(() => decrypt(key, aad, ciphertext)).toThrowError(
            "aes/gcm: invalid ghash tag",
        );
    });
});
