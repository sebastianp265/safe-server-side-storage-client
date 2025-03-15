import { asciiStringToBytes, random } from "../utils";
import { mac } from "../message-authentication";
import { describe, expect, test } from "vitest";

describe("message authentication", () => {
    test("should return the same mac after running twice on the same message", async () => {
        const key = random(32);
        const data = "Example of a message";
        const data_bytes = asciiStringToBytes(data);

        const mac_first_run = mac(data_bytes, key);
        const mac_second_run = mac(data_bytes, key);

        expect(mac_first_run).toEqual(mac_second_run);
    });

    test("should return different mac after running on a different message", async () => {
        const key = random(32);

        const data = "Example of a message";
        const data_bytes = asciiStringToBytes(data);
        const mac_first_run = mac(data_bytes, key);

        const different_message = "Same length message ";
        const different_message_bytes = asciiStringToBytes(different_message);
        const mac_second_run = mac(different_message_bytes, key);

        expect(mac_first_run).not.toEqual(mac_second_run);
    });
});
