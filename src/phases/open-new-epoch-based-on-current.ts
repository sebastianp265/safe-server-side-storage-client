import {
    CommonPublicKeyBundle,
    CommonPublicKeyBundleSerialized,
} from "../device/key-bundle/DeviceAndVirtualDeviceCommonKeyBundle";
import { VirtualDevicePublicKeyBundle } from "../device/key-bundle/VirtualDeviceKeyBundle";
import { Epoch, EpochWithoutId } from "../EpochStorage";
import { ThisDevice } from "../device/device";
import { kdfOneKey, kdfTwoKeys } from "../crypto/key-derivation";
import { asciiStringToBytes, bytes_equal, random } from "../crypto/utils";
import { bytesSerializerProvider } from "../BytesSerializerProvider";
import { generateEpochDeviceMac } from "./authenticate-device-to-epoch";
import { PublicKey } from "../crypto/keys";
import { encryptWithRandomNonce } from "../crypto/authenticated-symmetric-encryption";
import { labyrinth_hpke_encrypt } from "../crypto/public-key-encryption";

type DeviceInEpochSerialized = {
    id: string;
} & VirtualDeviceInEpochSerialized;

type VirtualDeviceInEpochSerialized = {
    mac: string;
    keyBundle: CommonPublicKeyBundleSerialized;
};

type DeviceInEpoch = {
    id: string;
} & VirtualDeviceInEpoch;

type VirtualDeviceInEpoch = {
    mac: Uint8Array;
    publicKeyBundle: VirtualDevicePublicKeyBundle;
};

export type GetDevicesInEpochResponse = {
    devices: DeviceInEpochSerialized[];
    virtualDevice: VirtualDeviceInEpochSerialized;
};

type EncryptedNewEpochEntropyForEveryDeviceInEpochSerialized = {
    deviceIdToEncryptedNewEpochEntropyMap: {
        [deviceId: string]: string;
    };
    virtualDeviceEncryptedNewEpochEntropy: string;
};

type EncryptedNewEpochEntropyForEveryDeviceInEpoch = {
    deviceIdToEncryptedNewEpochEntropyMap: {
        [deviceId: string]: Uint8Array;
    };
    virtualDeviceEncryptedNewEpochEntropy: Uint8Array;
};

type EncryptedCurrentEpochJoinData = {
    encryptedEpochSequenceId: string;
    encryptedEpochRootKey: string;
};

export type OpenNewEpochBasedOnCurrentBody = {
    encryptedNewEpochEntropyForEveryDeviceInEpoch: EncryptedNewEpochEntropyForEveryDeviceInEpochSerialized;
    newEpochMembershipProof: {
        epochThisDeviceMac: string;
        epochVirtualDeviceMac: string;
    };
    // encryptedCurrentEpochJoinData: EncryptedCurrentEpochJoinData;
};

export type OpenNewEpochBasedOnCurrentResponse = {
    openedEpochId: string;
};

export type OpenNewEpochBasedOnCurrentServerClient = {
    getDevicesInEpoch: (epochId: string) => Promise<GetDevicesInEpochResponse>;
    openNewEpochBasedOnCurrent: (
        currentEpochId: string,
        thisDeviceId: string,
        requestBody: OpenNewEpochBasedOnCurrentBody,
    ) => Promise<OpenNewEpochBasedOnCurrentResponse>;
};

export async function openNewEpochBasedOnCurrent(
    currentEpoch: Epoch,
    webClient: OpenNewEpochBasedOnCurrentServerClient,
    thisDevice: ThisDevice,
): Promise<Epoch> {
    const devicesInEpochPromise = webClient.getDevicesInEpoch(currentEpoch.id);
    const [epochChainingKey, epochDistributionPreSharedKey] = kdfTwoKeys(
        currentEpoch.rootKey,
        null,
        asciiStringToBytes(
            `epoch_chaining_${currentEpoch.sequenceId}_${currentEpoch.id}`,
        ),
    );

    const newEpochEntropy = random(32);
    const newEpochWithoutId: EpochWithoutId = {
        rootKey: kdfOneKey(
            newEpochEntropy,
            epochChainingKey,
            asciiStringToBytes("epoch_root_key"),
        ),
        sequenceId: (BigInt(currentEpoch.sequenceId) + BigInt(1)).toString(),
    };

    const devicesInEpoch = await devicesInEpochPromise;

    const encryptedNewEpochEntropyForEveryDeviceInEpoch =
        await encryptNewEpochEntropyForEveryDeviceInEpoch(
            currentEpoch,
            newEpochWithoutId,
            thisDevice,
            devicesInEpoch.devices.map((v) => {
                return {
                    id: v.id,
                    mac: bytesSerializerProvider.bytesSerializer.deserialize(
                        v.mac,
                    ),
                    publicKeyBundle: CommonPublicKeyBundle.deserialize(
                        v.keyBundle,
                    ),
                } as DeviceInEpoch;
            }),
            {
                mac: bytesSerializerProvider.bytesSerializer.deserialize(
                    devicesInEpoch.virtualDevice.mac,
                ),
                publicKeyBundle: CommonPublicKeyBundle.deserialize(
                    devicesInEpoch.virtualDevice.keyBundle,
                ),
            } as VirtualDeviceInEpoch,
            epochDistributionPreSharedKey,
            newEpochEntropy,
        );

    const { openedEpochId } = await webClient.openNewEpochBasedOnCurrent(
        currentEpoch.id,
        thisDevice.id,
        {
            encryptedNewEpochEntropyForEveryDeviceInEpoch: {
                deviceIdToEncryptedNewEpochEntropyMap: Object.fromEntries(
                    Object.entries(
                        encryptedNewEpochEntropyForEveryDeviceInEpoch.deviceIdToEncryptedNewEpochEntropyMap,
                    ).map((e) => {
                        const [k, v] = e;
                        return [
                            k,
                            bytesSerializerProvider.bytesSerializer.serialize(
                                v,
                            ),
                        ];
                    }),
                ),
                virtualDeviceEncryptedNewEpochEntropy:
                    bytesSerializerProvider.bytesSerializer.serialize(
                        encryptedNewEpochEntropyForEveryDeviceInEpoch.virtualDeviceEncryptedNewEpochEntropy,
                    ),
            },
            newEpochMembershipProof: {
                epochThisDeviceMac:
                    bytesSerializerProvider.bytesSerializer.serialize(
                        generateEpochDeviceMac(
                            newEpochWithoutId,
                            thisDevice.keyBundle.pub.deviceKeyPub,
                        ),
                    ),
                epochVirtualDeviceMac:
                    bytesSerializerProvider.bytesSerializer.serialize(
                        generateEpochDeviceMac(
                            newEpochWithoutId,
                            PublicKey.deserialize(
                                devicesInEpoch.virtualDevice.keyBundle
                                    .deviceKeyPub,
                            ),
                        ),
                    ),
            },
        },
    );

    return {
        id: openedEpochId,
        sequenceId: newEpochWithoutId.sequenceId,
        rootKey: newEpochWithoutId.rootKey,
    };
}

// @ts-ignore
async function encryptCurrentEpochJoinData(
    currentEpoch: Epoch,
    newEpochWithoutId: EpochWithoutId,
): Promise<EncryptedCurrentEpochJoinData> {
    const newEpochDataStorageKey = kdfOneKey(
        newEpochWithoutId.rootKey,
        null,
        asciiStringToBytes(
            `epoch_data_storage_${newEpochWithoutId.sequenceId}`,
        ),
    );

    const encryptedCurrentEpochSequenceId = encryptWithRandomNonce(
        newEpochDataStorageKey,
        asciiStringToBytes("epoch_data_metadata"),
        asciiStringToBytes(currentEpoch.sequenceId),
    );

    const encryptedCurrentEpochRootKey = encryptWithRandomNonce(
        newEpochDataStorageKey,
        asciiStringToBytes("epoch_data_metadata"),
        currentEpoch.rootKey,
    );

    return {
        encryptedEpochSequenceId:
            bytesSerializerProvider.bytesSerializer.serialize(
                encryptedCurrentEpochSequenceId,
            ),
        encryptedEpochRootKey:
            bytesSerializerProvider.bytesSerializer.serialize(
                encryptedCurrentEpochRootKey,
            ),
    };
}

export class InvalidVirtualDeviceServerRepresentationError extends Error {
    constructor() {
        super(
            "Epoch can't be opened when virtual device server representation is invalid",
        );

        Object.setPrototypeOf(
            this,
            InvalidVirtualDeviceServerRepresentationError.prototype,
        );
    }
}

async function encryptNewEpochEntropyForEveryDeviceInEpoch(
    currentEpoch: Epoch,
    newEpochWithoutId: EpochWithoutId,
    thisDevice: ThisDevice,
    devicesInEpoch: DeviceInEpoch[],
    virtualDeviceInEpoch: VirtualDeviceInEpoch,
    epochDistributionPreSharedKey: Uint8Array,
    newEpochEntropy: Uint8Array,
): Promise<EncryptedNewEpochEntropyForEveryDeviceInEpoch> {
    function encryptNewEpochEntropyForDeviceInEpoch(
        deviceInEpoch: VirtualDeviceInEpoch | DeviceInEpoch,
    ) {
        const expectedEpochDeviceMac = generateEpochDeviceMac(
            currentEpoch,
            deviceInEpoch.publicKeyBundle.deviceKeyPub,
        );

        if (!bytes_equal(deviceInEpoch.mac, expectedEpochDeviceMac)) {
            return null;
        }

        const isValidEpochStorageKey =
            deviceInEpoch.publicKeyBundle.deviceKeyPub.verify(
                deviceInEpoch.publicKeyBundle.epochStorageKeySig,
                Uint8Array.of(0x30),
                deviceInEpoch.publicKeyBundle.epochStorageKeyPub.getX25519PublicKeyBytes(),
            );

        if (!isValidEpochStorageKey) {
            return null;
        }

        return labyrinth_hpke_encrypt(
            deviceInEpoch.publicKeyBundle.epochStorageKeyPub,
            thisDevice.keyBundle.pub.epochStorageAuthKeyPub,
            thisDevice.keyBundle.priv.epochStorageAuthKeyPriv,
            epochDistributionPreSharedKey,
            asciiStringToBytes(`epoch_${newEpochWithoutId.sequenceId}`),
            newEpochEntropy,
        );
    }

    const virtualDeviceEncryptedNewEpochEntropy =
        encryptNewEpochEntropyForDeviceInEpoch(virtualDeviceInEpoch);
    if (virtualDeviceEncryptedNewEpochEntropy === null) {
        throw new InvalidVirtualDeviceServerRepresentationError();
    }

    const deviceIdToEncryptedNewEpochEntropyMap = Object.fromEntries(
        (
            await Promise.all(
                devicesInEpoch.map(
                    async (device) =>
                        [
                            device.id,
                            encryptNewEpochEntropyForDeviceInEpoch(device),
                        ] as const,
                ),
            )
        ).filter((e): e is [string, Uint8Array] => e[1] !== null),
    );

    return {
        deviceIdToEncryptedNewEpochEntropyMap,
        virtualDeviceEncryptedNewEpochEntropy,
    };
}
