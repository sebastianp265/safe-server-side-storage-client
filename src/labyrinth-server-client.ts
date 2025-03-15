import { OpenNewEpochBasedOnCurrentServerClient } from "./phases/open-new-epoch-based-on-current";
import { OpenFirstEpochServerClient } from "./phases/open-first-epoch";
import { JoinEpochServerClient } from "./phases/join-epoch";
import { GetVirtualDeviceRecoverySecretsServerClient } from "./device/virtual-device/VirtualDevice";
import { AuthenticateDeviceToEpochServerClient } from "./phases/authenticate-device-to-epoch";
import {
    CheckIfAnyDeviceExceedInactivityLimitServerClient,
    CheckIfLabyrinthIsInitializedServerClient,
    NotifyAboutDeviceActivityServerClient,
} from "./Labyrinth";
import { AuthenticateDeviceToEpochAndRegisterDeviceServerClient } from "./device/device";

export type LabyrinthServerClient = OpenFirstEpochServerClient &
    OpenNewEpochBasedOnCurrentServerClient &
    JoinEpochServerClient &
    GetVirtualDeviceRecoverySecretsServerClient &
    AuthenticateDeviceToEpochServerClient &
    CheckIfLabyrinthIsInitializedServerClient &
    AuthenticateDeviceToEpochAndRegisterDeviceServerClient &
    NotifyAboutDeviceActivityServerClient &
    CheckIfAnyDeviceExceedInactivityLimitServerClient;
