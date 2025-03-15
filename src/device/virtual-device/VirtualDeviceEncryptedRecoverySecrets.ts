import { bytesSerializerProvider } from "../../BytesSerializerProvider";
import { EpochWithoutId } from "../../EpochStorage";
import {
    VirtualDeviceKeyBundle,
    VirtualDevicePrivateKeyBundle,
    VirtualDevicePublicKeyBundle,
} from "../key-bundle/VirtualDeviceKeyBundle";
import {
    decrypt,
    encryptWithRandomNonce,
} from "../../crypto/authenticated-symmetric-encryption";
import {
    asciiStringToBytes,
    bytes_equal,
    bytesToAsciiString,
} from "../../crypto/utils";
import { PrivateKey } from "../../crypto/keys";

export type VirtualDeviceEncryptedRecoverySecretsSerialized = {
    encryptedEpochSequenceId: string;
    encryptedEpochRootKey: string;
    encryptedEpochStorageKeyPriv: string;
    encryptedDeviceKeyPriv: string;
};

export class VirtualDeviceEncryptedRecoverySecrets {
    public readonly encryptedEpochSequenceId: Uint8Array;
    public readonly encryptedEpochRootKey: Uint8Array;
    public readonly encryptedDeviceKeyPriv: Uint8Array;
    public readonly encryptedEpochStorageKeyPriv: Uint8Array;

    public constructor(
        encryptedEpochSequenceId: Uint8Array,
        encryptedEpochRootKey: Uint8Array,
        encryptedEpochStorageKeyPriv: Uint8Array,
        encryptedDeviceKeyPriv: Uint8Array,
    ) {
        this.encryptedEpochSequenceId = encryptedEpochSequenceId;
        this.encryptedEpochRootKey = encryptedEpochRootKey;
        this.encryptedEpochStorageKeyPriv = encryptedEpochStorageKeyPriv;
        this.encryptedDeviceKeyPriv = encryptedDeviceKeyPriv;
    }

    public static deserialize(
        virtualDeviceEncryptedRecoverSecretsSerialized: VirtualDeviceEncryptedRecoverySecretsSerialized,
    ): VirtualDeviceEncryptedRecoverySecrets {
        const {
            encryptedEpochSequenceId,
            encryptedEpochRootKey,
            encryptedEpochStorageKeyPriv,
            encryptedDeviceKeyPriv,
        } = virtualDeviceEncryptedRecoverSecretsSerialized;

        return new VirtualDeviceEncryptedRecoverySecrets(
            bytesSerializerProvider.bytesSerializer.deserialize(
                encryptedEpochSequenceId,
            ),
            bytesSerializerProvider.bytesSerializer.deserialize(
                encryptedEpochRootKey,
            ),
            bytesSerializerProvider.bytesSerializer.deserialize(
                encryptedEpochStorageKeyPriv,
            ),
            bytesSerializerProvider.bytesSerializer.deserialize(
                encryptedDeviceKeyPriv,
            ),
        );
    }

    public serialize(): VirtualDeviceEncryptedRecoverySecretsSerialized {
        return {
            encryptedEpochSequenceId:
                bytesSerializerProvider.bytesSerializer.serialize(
                    this.encryptedEpochSequenceId,
                ),
            encryptedEpochRootKey:
                bytesSerializerProvider.bytesSerializer.serialize(
                    this.encryptedEpochRootKey,
                ),
            encryptedEpochStorageKeyPriv:
                bytesSerializerProvider.bytesSerializer.serialize(
                    this.encryptedEpochStorageKeyPriv,
                ),
            encryptedDeviceKeyPriv:
                bytesSerializerProvider.bytesSerializer.serialize(
                    this.encryptedDeviceKeyPriv,
                ),
        };
    }
}

export function encryptVirtualDeviceRecoverySecrets(
    virtualDeviceDecryptionKey: Uint8Array,
    epochWithoutId: EpochWithoutId,
    virtualDevicePrivateKeyBundle: VirtualDevicePrivateKeyBundle,
): VirtualDeviceEncryptedRecoverySecrets {
    const encryptedEpochSequenceId = encryptWithRandomNonce(
        virtualDeviceDecryptionKey,
        asciiStringToBytes("virtual_device:epoch_anon_id"),
        asciiStringToBytes(epochWithoutId.sequenceId),
    );

    const encryptedEpochRootKey = encryptWithRandomNonce(
        virtualDeviceDecryptionKey,
        asciiStringToBytes("virtual_device:epoch_root_key"),
        epochWithoutId.rootKey,
    );

    const encryptedDeviceKeyPriv = encryptWithRandomNonce(
        virtualDeviceDecryptionKey,
        asciiStringToBytes("virtual_device:virtual_device_private_key"),
        asciiStringToBytes(
            virtualDevicePrivateKeyBundle.deviceKeyPriv.serialize(),
        ),
    );

    const encryptedEpochStorageKeyPriv = encryptWithRandomNonce(
        virtualDeviceDecryptionKey,
        asciiStringToBytes("virtual_device:epoch_storage_key_priv"),
        asciiStringToBytes(
            virtualDevicePrivateKeyBundle.epochStorageKeyPriv.serialize(),
        ),
    );

    return new VirtualDeviceEncryptedRecoverySecrets(
        encryptedEpochSequenceId,
        encryptedEpochRootKey,
        encryptedEpochStorageKeyPriv,
        encryptedDeviceKeyPriv,
    );
}

export class CorruptedMessageRecoverySecrets extends Error {
    constructor() {
        super("Your message history recovery secrets has been corrupted");

        Object.setPrototypeOf(this, CorruptedMessageRecoverySecrets.prototype);
    }
}

export function decryptVirtualDeviceRecoverySecrets(
    virtualDeviceDecryptionKey: Uint8Array,
    virtualDeviceEncryptedRecoverySecrets: VirtualDeviceEncryptedRecoverySecrets,
    expectedVirtualDevicePublicKeyBundle: VirtualDevicePublicKeyBundle,
): {
    epochWithoutId: EpochWithoutId;
    virtualDeviceKeyBundle: VirtualDeviceKeyBundle;
} {
    const epochSequenceId = bytesToAsciiString(
        decrypt(
            virtualDeviceDecryptionKey,
            asciiStringToBytes("virtual_device:epoch_anon_id"),
            virtualDeviceEncryptedRecoverySecrets.encryptedEpochSequenceId,
        ),
    );

    const epochRootKey = decrypt(
        virtualDeviceDecryptionKey,
        asciiStringToBytes("virtual_device:epoch_root_key"),
        virtualDeviceEncryptedRecoverySecrets.encryptedEpochRootKey,
    );

    const deviceKeyPriv = PrivateKey.deserialize(
        bytesToAsciiString(
            decrypt(
                virtualDeviceDecryptionKey,
                asciiStringToBytes("virtual_device:virtual_device_private_key"),
                virtualDeviceEncryptedRecoverySecrets.encryptedDeviceKeyPriv,
            ),
        ),
    );

    const epochStorageKeyPriv = PrivateKey.deserialize(
        bytesToAsciiString(
            decrypt(
                virtualDeviceDecryptionKey,
                asciiStringToBytes("virtual_device:epoch_storage_key_priv"),
                virtualDeviceEncryptedRecoverySecrets.encryptedEpochStorageKeyPriv,
            ),
        ),
    );

    const virtualDevicePrivateKeyBundle = new VirtualDevicePrivateKeyBundle(
        deviceKeyPriv,
        epochStorageKeyPriv,
    );
    const virtualDeviceKeyBundle = new VirtualDeviceKeyBundle(
        virtualDevicePrivateKeyBundle,
        virtualDevicePrivateKeyBundle.getPublicKeyBundle(),
    );

    if (
        !isVirtualDevicePublicKeyBundleValid(
            expectedVirtualDevicePublicKeyBundle,
            virtualDeviceKeyBundle.pub,
        )
    ) {
        throw new CorruptedMessageRecoverySecrets();
    }

    return {
        virtualDeviceKeyBundle,
        epochWithoutId: {
            rootKey: epochRootKey,
            sequenceId: epochSequenceId,
        },
    };
}

function isVirtualDevicePublicKeyBundleValid(
    expected: VirtualDevicePublicKeyBundle,
    actual: VirtualDevicePublicKeyBundle,
): boolean {
    return (
        expected.deviceKeyPub.equals(actual.deviceKeyPub) &&
        bytes_equal(expected.epochStorageKeySig, actual.epochStorageKeySig) &&
        expected.epochStorageKeyPub.equals(actual.epochStorageKeyPub)
    );
}
