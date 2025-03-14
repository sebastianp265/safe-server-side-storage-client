export interface BytesSerializer {
    serialize: (bytes: Uint8Array) => string;
    deserialize: (serialized: string) => Uint8Array;
}
