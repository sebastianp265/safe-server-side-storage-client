export interface BytesSerializer {
    serialize: (bytes: Uint8Array) => string;
    deserialize: (serialized: string) => Uint8Array;
}

class BytesSerializerProvider {
    private _bytesSerializer: BytesSerializer | null = null;

    public set bytesSerializer(bytesSerializer: BytesSerializer) {
        this._bytesSerializer = bytesSerializer;
    }

    public get bytesSerializer(): BytesSerializer {
        if (this._bytesSerializer == null) {
            throw new Error(
                "BytesSerializer is not set. Please assign a valid BytesSerializer instance using 'bytesSerializerProvider.bytesSerializer = yourSerializer'.",
            );
        }
        return this._bytesSerializer;
    }
}

export const bytesSerializerProvider = new BytesSerializerProvider();
