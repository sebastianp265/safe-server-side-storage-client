import { random } from "@/crypto/utils.ts";
import { generateEpochDeviceMac } from "@/phases/authenticate-device-to-epoch.ts";
import { Epoch, EpochWithoutId } from "@/EpochStorage.ts";
import {
    DevicePublicKeyBundle,
    DevicePublicKeyBundleSerialized,
} from "@/device/key-bundle/DeviceKeyBundle.ts";
import { VirtualDevice } from "@/device/virtual-device/VirtualDevice.ts";
import {
    encryptVirtualDeviceRecoverySecrets,
    VirtualDeviceEncryptedRecoverySecretsSerialized,
} from "@/device/virtual-device/VirtualDeviceEncryptedRecoverySecrets.ts";
import { VirtualDevicePublicKeyBundleSerialized } from "@/device/key-bundle/VirtualDeviceKeyBundle.ts";
import { bytesSerializerProvider } from "@/BytesSerializerProvider.ts";

export type OpenFirstEpochBody = {
    virtualDeviceId: string;
    virtualDeviceEncryptedRecoverySecrets: VirtualDeviceEncryptedRecoverySecretsSerialized;
    virtualDevicePublicKeyBundle: VirtualDevicePublicKeyBundleSerialized;
    devicePublicKeyBundle: DevicePublicKeyBundleSerialized;
    firstEpochMembershipProof: {
        epochDeviceMac: string;
        epochVirtualDeviceMac: string;
    };
};

export type OpenFirstEpochResponse = {
    deviceId: string;
    epochId: string;
};

export type OpenFirstEpochServerClient = {
    openFirstEpoch: (
        requestBody: OpenFirstEpochBody,
    ) => Promise<OpenFirstEpochResponse>;
};

export async function openFirstEpoch(
    devicePublicKeyBundle: DevicePublicKeyBundle,
    virtualDeviceDecryptionKey: Uint8Array,
    virtualDevice: VirtualDevice,
    serverClient: OpenFirstEpochServerClient,
): Promise<{ deviceId: string; firstEpoch: Epoch }> {
    const firstEpochWithoutId: EpochWithoutId = {
        sequenceId: "0",
        rootKey: random(32),
    };

    const epochVirtualDeviceMac = generateEpochDeviceMac(
        firstEpochWithoutId,
        virtualDevice.keyBundle.pub.deviceKeyPub,
    );

    const epochThisDeviceMac = generateEpochDeviceMac(
        firstEpochWithoutId,
        devicePublicKeyBundle.deviceKeyPub,
    );

    const virtualDeviceEncryptedRecoverySecrets =
        encryptVirtualDeviceRecoverySecrets(
            virtualDeviceDecryptionKey,
            firstEpochWithoutId,
            virtualDevice.keyBundle.priv,
        );

    const openFirstEpochResponse = await serverClient.openFirstEpoch({
        virtualDeviceId: bytesSerializerProvider.bytesSerializer.serialize(
            virtualDevice.id,
        ),
        firstEpochMembershipProof: {
            epochDeviceMac:
                bytesSerializerProvider.bytesSerializer.serialize(
                    epochThisDeviceMac,
                ),
            epochVirtualDeviceMac:
                bytesSerializerProvider.bytesSerializer.serialize(
                    epochVirtualDeviceMac,
                ),
        },
        devicePublicKeyBundle: devicePublicKeyBundle.serialize(),
        virtualDevicePublicKeyBundle: virtualDevice.keyBundle.pub.serialize(),
        virtualDeviceEncryptedRecoverySecrets:
            virtualDeviceEncryptedRecoverySecrets.serialize(),
    });

    const firstEpoch = {
        id: openFirstEpochResponse.epochId,
        ...firstEpochWithoutId,
    } as Epoch;

    return {
        deviceId: openFirstEpochResponse.deviceId,
        firstEpoch,
    };
}
