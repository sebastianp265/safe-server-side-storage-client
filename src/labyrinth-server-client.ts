import { OpenFirstEpochServerClient } from "@/phases/open-first-epoch.ts";
import { JoinEpochServerClient } from "@/phases/join-epoch.ts";
import { AuthenticateDeviceToEpochServerClient } from "@/phases/authenticate-device-to-epoch.ts";
import {
    CheckIfAnyDeviceExceedInactivityLimitServerClient,
    CheckIfLabyrinthIsInitializedServerClient,
    NotifyAboutDeviceActivityServerClient,
} from "@/Labyrinth.ts";
import { GetVirtualDeviceRecoverySecretsServerClient } from "@/device/virtual-device/VirtualDevice.ts";
import { OpenNewEpochBasedOnCurrentServerClient } from "@/phases/open-new-epoch-based-on-current.ts";
import { AuthenticateDeviceToEpochAndRegisterDeviceServerClient } from "@/device/device.ts";

export type LabyrinthServerClient = OpenFirstEpochServerClient &
    OpenNewEpochBasedOnCurrentServerClient &
    JoinEpochServerClient &
    GetVirtualDeviceRecoverySecretsServerClient &
    AuthenticateDeviceToEpochServerClient &
    CheckIfLabyrinthIsInitializedServerClient &
    AuthenticateDeviceToEpochAndRegisterDeviceServerClient &
    NotifyAboutDeviceActivityServerClient &
    CheckIfAnyDeviceExceedInactivityLimitServerClient;
