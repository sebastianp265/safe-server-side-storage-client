import { ThisDevice, ThisDeviceSerialized } from "./device/device";
import { Epoch, EpochStorage, EpochStorageSerialized } from "./EpochStorage";
import { LabyrinthServerClient } from "./labyrinth-server-client";
import { VirtualDevice } from "./device/virtual-device/VirtualDevice";
import { joinAllEpochs } from "./phases/join-epoch";
import {
    decrypt,
    encryptWithRandomNonce,
} from "./crypto/authenticated-symmetric-encryption";
import { asciiStringToBytes } from "./crypto/utils";
import { kdfOneKey } from "./crypto/key-derivation";
import { openNewEpochBasedOnCurrent } from "./phases/open-new-epoch-based-on-current";

export type LabyrinthSerialized = {
    thisDevice: ThisDeviceSerialized;
    epochStorage: EpochStorageSerialized;
};

export type CheckIfLabyrinthIsInitializedResponse = {
    isInitialized: boolean;
};

export type CheckIfLabyrinthIsInitializedServerClient = {
    checkIfLabyrinthIsInitialized: () => Promise<CheckIfLabyrinthIsInitializedResponse>;
};

export type NotifyAboutDeviceActivityServerClient = {
    notifyAboutDeviceActivity: (deviceId: string) => Promise<void>;
};

export type CheckIfAnyDeviceExceedInactivityLimitResponseDTO = {
    didAnyDeviceExceedInactivityLimit: boolean;
};

export type CheckIfAnyDeviceExceedInactivityLimitServerClient = {
    checkIfAnyDeviceExceedInactivityLimit: () => Promise<CheckIfAnyDeviceExceedInactivityLimitResponseDTO>;
};

export class Labyrinth {
    private readonly thisDevice: ThisDevice;
    private readonly epochStorage: EpochStorage;

    public static async checkIfLabyrinthIsInitialized(
        labyrinthServerClient: LabyrinthServerClient,
    ) {
        return await labyrinthServerClient.checkIfLabyrinthIsInitialized();
    }

    public static async initialize(
        userId: string,
        labyrinthServerClient: LabyrinthServerClient,
    ) {
        const { virtualDevice, virtualDeviceDecryptionKey, recoveryCode } =
            VirtualDevice.initialize(userId);

        const { firstEpoch, thisDevice } = await ThisDevice.initialize(
            virtualDevice,
            virtualDeviceDecryptionKey,
            labyrinthServerClient,
        );

        const epochStorage = EpochStorage.createEmpty();
        epochStorage.add(firstEpoch);

        const labyrinthInstance = new Labyrinth(thisDevice, epochStorage);

        return {
            labyrinthInstance,
            recoveryCode,
        };
    }

    public static async fromRecoveryCode(
        userId: string,
        recoveryCode: string,
        labyrinthServerClient: LabyrinthServerClient,
    ): Promise<Labyrinth> {
        const { virtualDevice, epoch } = await VirtualDevice.fromRecoveryCode(
            userId,
            recoveryCode,
            labyrinthServerClient,
        );

        const epochStorage = EpochStorage.createEmpty();
        epochStorage.add(epoch);

        await joinAllEpochs(virtualDevice, epochStorage, labyrinthServerClient);

        const newestRecoveredEpoch = epochStorage.getNewestEpoch();
        const thisDevice = await ThisDevice.fromRecoveryCode(
            newestRecoveredEpoch,
            labyrinthServerClient,
        );

        await labyrinthServerClient.notifyAboutDeviceActivity(thisDevice.id);
        await checkIfAnyDeviceExceededInactivityLimitAndOpenNewEpochIfNeeded(
            labyrinthServerClient,
            thisDevice,
            epochStorage,
        );
        return new Labyrinth(thisDevice, epochStorage);
    }

    public static async deserialize(
        labyrinthSerialized: LabyrinthSerialized,
        labyrinthServerClient: LabyrinthServerClient,
    ): Promise<Labyrinth> {
        const {
            thisDevice: thisDeviceSerialized,
            epochStorage: epochStorageSerialized,
        } = labyrinthSerialized;
        const epochStorage = EpochStorage.deserialize(epochStorageSerialized);
        const thisDevice = await ThisDevice.deserialize(
            thisDeviceSerialized,
            epochStorage,
            labyrinthServerClient,
        );

        await labyrinthServerClient.notifyAboutDeviceActivity(thisDevice.id);
        await checkIfAnyDeviceExceededInactivityLimitAndOpenNewEpochIfNeeded(
            labyrinthServerClient,
            thisDevice,
            epochStorage,
        );
        return new Labyrinth(thisDevice, epochStorage);
    }

    public serialize(): LabyrinthSerialized {
        return {
            thisDevice: this.thisDevice.serialize(),
            epochStorage: this.epochStorage.serialize(),
        };
    }

    private constructor(thisDevice: ThisDevice, epochStorage: EpochStorage) {
        this.thisDevice = thisDevice;
        this.epochStorage = epochStorage;
    }

    public encrypt(
        threadId: string,
        epochSequenceId: string,
        plaintext: Uint8Array,
    ): Uint8Array {
        return encryptWithRandomNonce(
            deriveMessageKey(
                threadId,
                this.epochStorage.getEpoch(epochSequenceId),
            ),
            asciiStringToBytes(`message_thread_${threadId}`),
            plaintext,
        );
    }

    public decrypt(
        threadId: string,
        epochSequenceId: string,
        ciphertext: Uint8Array,
    ): Uint8Array {
        return decrypt(
            deriveMessageKey(
                threadId,
                this.epochStorage.getEpoch(epochSequenceId),
            ),
            asciiStringToBytes(`message_thread_${threadId}`),
            ciphertext,
        );
    }

    public getNewestEpochSequenceId() {
        return this.epochStorage.getNewestEpoch().sequenceId;
    }

    public getNewestEpochId() {
        return this.epochStorage.getNewestEpoch().id;
    }
}

const CIPHER_VERSION = 1;

function deriveMessageKey(threadId: string, epoch: Epoch) {
    return kdfOneKey(
        epoch.rootKey,
        null,
        asciiStringToBytes(
            `message_key_in_epoch_${epoch.sequenceId}_cipher_version_${CIPHER_VERSION}_${threadId}`,
        ),
    );
}

async function checkIfAnyDeviceExceededInactivityLimitAndOpenNewEpochIfNeeded(
    labyrinthServerClient: LabyrinthServerClient,
    thisDevice: ThisDevice,
    epochStorage: EpochStorage,
) {
    const { didAnyDeviceExceedInactivityLimit } =
        await labyrinthServerClient.checkIfAnyDeviceExceedInactivityLimit();

    if (didAnyDeviceExceedInactivityLimit) {
        const newCreatedEpoch = await openNewEpochBasedOnCurrent(
            epochStorage.getNewestEpoch(),
            labyrinthServerClient,
            thisDevice,
        );
        epochStorage.add(newCreatedEpoch);
    }
}
