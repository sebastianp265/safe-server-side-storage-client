import { generateKeyPair, PrivateKey, PublicKey } from "./keys";
import { concat, cryptoAssert } from "./utils";
import { kdfOneKey, KEY_LENGTH_BYTES } from "./key-derivation";
import {
    decrypt,
    encrypt,
    NONCE_LENGTH,
} from "./authenticated-symmetric-encryption";

export function labyrinth_hpke_encrypt(
    recipient_enc_pub: PublicKey,
    sender_auth_pub: PublicKey,
    sender_auth_priv: PrivateKey,
    psk: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
) {
    cryptoAssert(psk.length === KEY_LENGTH_BYTES);

    const { publicKey: pub_ephem, privateKey: priv_ephem } = generateKeyPair();
    const id_id = sender_auth_priv.agree(recipient_enc_pub);
    const id_ephem = priv_ephem.agree(recipient_enc_pub);

    const fresh_secret = concat(id_id, id_ephem);
    const inner_aad = concat(
        Uint8Array.of(0x01),
        sender_auth_pub.getX25519PublicKeyBytes(),
        recipient_enc_pub.getX25519PublicKeyBytes(),
        pub_ephem.getX25519PublicKeyBytes(),
        aad,
    );

    const subkey = kdfOneKey(fresh_secret, psk, inner_aad);
    const nonce = new Uint8Array(NONCE_LENGTH);
    const ciphertext = encrypt(subkey, nonce, aad, plaintext);
    return concat(
        Uint8Array.of(0x01),
        pub_ephem.getEd25519PublicKeyBytes(),
        ciphertext,
    );
}

export function labyrinth_hpke_decrypt(
    recipient_enc_pub: PublicKey,
    recipient_enc_priv: PrivateKey,
    sender_auth_pub: PublicKey,
    psk: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array,
) {
    cryptoAssert(psk.length === KEY_LENGTH_BYTES);
    const use_case_byte = ciphertext.subarray(0, 1);
    cryptoAssert(use_case_byte.length == 1 && use_case_byte[0] == 0x01);

    const pub_ephem = new PublicKey(
        ciphertext.subarray(1, 1 + KEY_LENGTH_BYTES),
    );
    ciphertext = ciphertext.subarray(1 + KEY_LENGTH_BYTES);

    const id_id = recipient_enc_priv.agree(sender_auth_pub);
    const id_ephem = recipient_enc_priv.agree(pub_ephem);

    const fresh_secret = concat(id_id, id_ephem);
    const inner_aad = concat(
        Uint8Array.of(0x01),
        sender_auth_pub.getX25519PublicKeyBytes(),
        recipient_enc_pub.getX25519PublicKeyBytes(),
        pub_ephem.getX25519PublicKeyBytes(),
        aad,
    );
    const subkey = kdfOneKey(fresh_secret, psk, inner_aad);
    return decrypt(subkey, aad, ciphertext);
}
