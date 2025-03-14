import { asciiStringToBytes, bytesToAsciiString } from "@/crypto/utils.ts";
import { describe, expect, test } from "vitest";

describe("utils test", () => {
    test("Converting all possible bytes to ascii string is reversible", () => {
        const allPossibleBytes = Uint8Array.of(
            ...Array.from({ length: 256 }, (_, i) => i),
        );

        const asciiFromBytes = bytesToAsciiString(allPossibleBytes);
        const bytesFromAscii = asciiStringToBytes(asciiFromBytes);

        expect(bytesFromAscii).toStrictEqual(allPossibleBytes);
    });
});
