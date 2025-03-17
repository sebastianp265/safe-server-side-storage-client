import {
    DeviceKeyBundle,
    DeviceKeyBundleSerialized,
    DevicePublicKeyBundleSerialized,
} from "./key-bundles/DeviceKeyBundle";
import { Epoch, EpochStorage } from "../EpochStorage";
import { LabyrinthServerClient } from "../labyrinth-server-client";
import { joinAllEpochs } from "../phases/join-epoch";
import { generateEpochDeviceMac } from "../phases/authenticate-device-to-epoch";
import { VirtualDevice } from "./virtual-device/VirtualDevice";
import {
    openFirstEpoch,
    OpenFirstEpochServerClient,
} from "../phases/open-first-epoch";
import { bytesSerializerProvider } from "../BytesSerializer";

export type AuthenticateDeviceToEpochAndRegisterDeviceResponse = {
    assignedDeviceId: string;
};

export type AuthenticateDeviceToEpochAndRegisterDeviceRequestBody = {
    devicePublicKeyBundle: DevicePublicKeyBundleSerialized;
    epochDeviceMac: string;
};

export type AuthenticateDeviceToEpochAndRegisterDeviceServerClient = {
    authenticateDeviceToEpochAndRegisterDevice: (
        epochId: string,
        requestBody: AuthenticateDeviceToEpochAndRegisterDeviceRequestBody,
    ) => Promise<AuthenticateDeviceToEpochAndRegisterDeviceResponse>;
};

export type ThisDeviceSerialized = {
    id: string;
    keyBundle: DeviceKeyBundleSerialized;
};

export class ThisDevice {
    public readonly id: string;
    public readonly keyBundle: DeviceKeyBundle;

    private constructor(id: string, keyBundle: DeviceKeyBundle) {
        this.id = id;
        this.keyBundle = keyBundle;
    }

    public static async deserialize(
        thisDeviceSerialized: ThisDeviceSerialized,
        epochStorage: EpochStorage,
        labyrinthServerClient: LabyrinthServerClient,
    ): Promise<ThisDevice> {
        const thisDevice = new ThisDevice(
            thisDeviceSerialized.id,
            DeviceKeyBundle.deserialize(thisDeviceSerialized.keyBundle),
        );

        const newestEpochSequenceIdBefore =
            epochStorage.getNewestEpoch().sequenceId;
        await joinAllEpochs(thisDevice, epochStorage, labyrinthServerClient);
        const newestEpochAfter = epochStorage.getNewestEpoch();

        if (newestEpochSequenceIdBefore != newestEpochAfter.sequenceId) {
            await labyrinthServerClient.authenticateDeviceToEpoch(
                newestEpochAfter.id,
                thisDevice.id,
                {
                    epochDeviceMac:
                        bytesSerializerProvider.bytesSerializer.serialize(
                            generateEpochDeviceMac(
                                newestEpochAfter,
                                thisDevice.keyBundle.pub.deviceKeyPub,
                            ),
                        ),
                },
            );
        }

        return new ThisDevice(
            thisDeviceSerialized.id,
            DeviceKeyBundle.deserialize(thisDeviceSerialized.keyBundle),
        );
    }

    public serialize(): ThisDeviceSerialized {
        return {
            id: this.id,
            keyBundle: this.keyBundle.serialize(),
        };
    }

    public static async initialize(
        virtualDevice: VirtualDevice,
        virtualDeviceDecryptionKey: Uint8Array,
        labyrinthWebClient: OpenFirstEpochServerClient,
    ) {
        const deviceKeyBundle = DeviceKeyBundle.generate();

        const { deviceId, firstEpoch } = await openFirstEpoch(
            deviceKeyBundle.pub,
            virtualDeviceDecryptionKey,
            virtualDevice,
            labyrinthWebClient,
        );

        const thisDevice = new ThisDevice(deviceId, deviceKeyBundle);

        return {
            thisDevice,
            firstEpoch,
        };
    }

    public static async fromRecoveryCode(
        newestRecoveredEpoch: Epoch,
        webClient: AuthenticateDeviceToEpochAndRegisterDeviceServerClient,
    ) {
        const deviceKeyBundle = DeviceKeyBundle.generate();

        const { assignedDeviceId } =
            await webClient.authenticateDeviceToEpochAndRegisterDevice(
                newestRecoveredEpoch.id,
                {
                    devicePublicKeyBundle: deviceKeyBundle.pub.serialize(),
                    epochDeviceMac:
                        bytesSerializerProvider.bytesSerializer.serialize(
                            generateEpochDeviceMac(
                                newestRecoveredEpoch,
                                deviceKeyBundle.pub.deviceKeyPub,
                            ),
                        ),
                },
            );

        return new ThisDevice(assignedDeviceId, deviceKeyBundle);
    }
}
