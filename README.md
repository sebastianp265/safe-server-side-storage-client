# Library for Confidential Server-Side Message Storage

## About

This library was developed as part of my PhD thesis, presenting the design and implementation of a client library that enables secure storage of messages on the server side using the [Labyrinth protocol](https://engineering.fb.com/wp-content/uploads/2023/12/TheLabyrinthEncryptedMessageStorageProtocol_12-6-2023.pdf) developed by Meta.

The purpose of this library is to facilitate discussions, analysis, and improvements of the protocol while also detailing certain issues that may be helpful for further development.

## Install

Library can be installed via npm:
```shell
npm i @sebastianp265/safe-server-side-storage-client
```

## Usage

Example usages are provided below. Additionally, real-life usage can be found in the repository [e2ee-chat-with-labyrinth](https://github.com/sebastianp265/e2ee-chat-with-labyrinth), 
which demonstrates integration in a messaging app using React.

### Server-side communication

Library requires to implement communication with the server through LabyrinthServerClient API:
```typescript
const labyrinthServerClient: LabyrinthServerClient = {
    /*
        Implementation of API layer communication
    */
    // For example:
    openFirstEpoch: async (requestBody) =>
        (
            await httpClient.post<OpenFirstEpochResponse>(
                `${labyrinthServicePrefix}/epochs/open-first`,
                requestBody,
            )
        ).data,
};
```


### Initialization

All actions are available via Labyrinth instance, which must be created using static methods based on the scenario.

#### First time (Recovery code is generated)

```typescript
const userId = "example-user-id";
const { labyrinthInstance, recoveryCode } = await Labyrinth.initialize(
    userId,
    labyrinthServerClient,
);
```

#### First time on new device (Recovery code must be inserted)

```typescript
const userId = "example-user-id";
const labyrinthInstance = await Labyrinth.fromRecoveryCode(
    userId,
    recoveryCode,
    labyrinthServerClient,
);
```

#### Logging again on the same device (Deserializing stored instance)

```typescript
// For example:
const labyrinthSerialized = JSON.parse(localStorage.getItem("labyrinth"))
const labyrinthInstance = await Labyrinth.deserialize(labyrinthSerialized, labyrinthServerClient)
```

### Encryption 

```typescript
const textEncoder = new TextEncoder();
const exampleMessage = JSON.stringify({
    content: "example-message-content",
    authorId: "example-author-id",
});
const encryptedMessage = labyrinthInstance.encrypt(
    "example-thread-id",
    labyrinthInstance.getNewestEpochSequenceId(),
    textEncoder.encode(exampleMessage),
);
```

### Decryption

```typescript
const textDecoder = new TextDecoder();
const decryptedMessage = textDecoder.decode(
    labyrinthInstance.decrypt(
        "example-thread-id",
        labyrinthInstance.getNewestEpochSequenceId(),
        encryptedMessage,
    ),
);
assert(decryptedMessage == exampleMessage);
```

### Storing instance

```typescript
// For example:
localStorage.setItem("labyrinth", JSON.stringify(
    labyrinthInstance.serialize()
));
```

## Contributing

Contributions are welcome! Feel free to open issues and submit pull requests.

## Tests

The code is not fully covered with tests inside this repository. However, the library is fully functional and has been tested from a usage perspective with Cypress tests in the [e2ee-chat-with-labyrinth](https://github.com/sebastianp265/e2ee-chat-with-labyrinth) repository.

To run existing tests:
```shell
npm run test
```

And check code-coverage:
```shell
npm run coverage
```

## Disclaimer

This library is not yet production-ready and does not guarantee to be secure. It is provided "as is" without any warranties or guarantees of any kind. I take no responsibility for any use, misuse, or consequences arising from the use of this code. Use it at your own risk.