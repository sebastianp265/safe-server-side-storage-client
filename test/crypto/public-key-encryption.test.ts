import {
    labyrinth_hpke_decrypt,
    labyrinth_hpke_encrypt,
} from "@/crypto/public-key-encryption.ts";
import { asciiStringToBytes, random } from "@/crypto/utils.ts";
import { generateKeyPair } from "@/crypto/keys.ts";
import { expect, test } from "vitest";
import { KEY_LENGTH_BYTES } from "@/crypto/key-derivation.ts";

test("sender encrypts the message and recipient decrypts it correctly", async () => {
    // psk is shared before encryption
    const psk = random(KEY_LENGTH_BYTES);

    // recipient encryption key pair
    const { publicKey: recipient_enc_pub, privateKey: recipient_enc_priv } =
        generateKeyPair();

    // sender authorization key pair
    const { publicKey: sender_auth_pub, privateKey: sender_auth_priv } =
        generateKeyPair();
    const aad = random(8);

    // operations on sender side
    const plaintext = asciiStringToBytes("Hello Alice!");
    const ciphertext = labyrinth_hpke_encrypt(
        recipient_enc_pub,
        sender_auth_pub,
        sender_auth_priv,
        psk,
        aad,
        plaintext,
    );

    // operation on recipient side
    const decrypted_plaintext = labyrinth_hpke_decrypt(
        recipient_enc_pub,
        recipient_enc_priv,
        sender_auth_pub,
        psk,
        aad,
        ciphertext,
    );

    expect(decrypted_plaintext).toEqual(plaintext);
});
