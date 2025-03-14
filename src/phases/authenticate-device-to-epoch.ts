import { kdfOneKey } from "@/crypto/key-derivation.ts";
import { mac } from "@/crypto/message-authentication.ts";
import { Epoch, EpochWithoutId } from "@/EpochStorage.ts";
import { PublicKey } from "@/crypto/keys.ts";
import { asciiStringToBytes } from "@/crypto/utils.ts";

export type AuthenticateDeviceToEpochRequestBody = {
    epochDeviceMac: string;
};

export type AuthenticateDeviceToEpochServerClient = {
    authenticateDeviceToEpoch: (
        epochId: string,
        deviceId: string,
        authenticateDeviceToEpochRequestBody: AuthenticateDeviceToEpochRequestBody,
    ) => Promise<void>;
};

export function generateEpochDeviceMac(
    epoch: Epoch | EpochWithoutId,
    deviceKeyPub: PublicKey,
) {
    const epochDeviceMacKey = kdfOneKey(
        epoch.rootKey,
        null,
        // TODO: why in protocol there is base64 encoding?
        asciiStringToBytes(`epoch_devices_${epoch.sequenceId}`),
    );

    return mac(epochDeviceMacKey, deviceKeyPub.getX25519PublicKeyBytes());
}
