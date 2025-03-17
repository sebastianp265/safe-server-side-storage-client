import {
    encryptVirtualDeviceRecoverySecrets,
    VirtualDeviceEncryptedRecoverySecretsSerialized,
} from "../device/virtual-device/VirtualDeviceEncryptedRecoverySecrets";
import { VirtualDevicePublicKeyBundleSerialized } from "../device/key-bundles/VirtualDeviceKeyBundle";
import {
    DevicePublicKeyBundle,
    DevicePublicKeyBundleSerialized,
} from "../device/key-bundles/DeviceKeyBundle";
import { VirtualDevice } from "../device/virtual-device/VirtualDevice";
import { Epoch, EpochWithoutId } from "../EpochStorage";
import { random } from "../crypto/utils";
import { generateEpochDeviceMac } from "./authenticate-device-to-epoch";
import { bytesSerializerProvider } from "../BytesSerializer";

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
