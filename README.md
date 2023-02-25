# Prism Lib

Checkout our **[live web demo!](https://app-demo.prism.chat/)**

The Prism Chat Library for E2E, anonymous and decentralized communication built on [libsodium](https://doc.libsodium.org/). We have used [libsodium](https://doc.libsodium.org/) as the base for all of our cryptographic operations as it gives and easy to use interface as well as known security. This allows us to focus on the higher level cryptographic logic that makes Prism what it is.

## Usage

PrismChat-lib has been packaged in a node module for easy deployment and is essentially a single class. This class stores the state of the users Identity Keys which are used for most cryptographic operations. PrismChat-lib also exposes all of the pure functions included in [libsodium](https://doc.libsodium.org/). This approach allows us to easily perform Prism specific encryption operations utalizing tis own state, or any pure functions of [libsodium](https://doc.libsodium.org/), not relying on any state.

### Instantiation

When creating a new Prism instance it can be created with or without identity keys, but they are required by the class to perform cryptographic operations. You can include them at instantiation as parameters to the constructor or create them after instantiation with a function that will both update the state of the instance and return the string values.

``` javascript
const Alice = new Prism();
await Alice.init();

// Function will both update state and return values
const {public, private} = Alice.generateIdentityKeys(); 
```

``` javascript
const Alice = new Prism(Public, Private);
await Alice.init();

// Access Identity Key state after instantiation
const {public, private} = Alice.IdentityKeys; 
```

### Accessing the sodium instance

You can access the sodium instance and all of its pure functions by accessing the ```sodium``` property of a prism object. Below is an example of how to access the base64 encoding function of [libsodium](https://doc.libsodium.org/). It could be noted that all base64 encoding for Prism is done with the ```URLSAFE_NO_PADDING``` variant.

``` javascript
const Alice = new Prism(Public, Private);
await Alice.init();

const base64EncodedString = Alice.sodium.to_base64(
  "Hello World!",
  Alice.sodium.base64_variants.URLSAFE_NO_PADDING
);
```

### Performing Prism key exchange

When chatting with Prism we use a key exchange method to generate session keys for each specific chat you are engaged in. This is done by generating random and unique session keys independently, exchanging the public key for the session, and then independently calculating the same shared keys. After each message the keys should be modified via the derivation function to ensure forward security. Below is an example of that key exchange.

``` javascript
const Alice = new Prism();
await Alice.init();
Alice.generateIdentityKeys(); 
const aliceSessionKeys = Alice.generateSessionKeys();

const Bob = new Prism();
await Bob.init();
Bob.generateIdentityKeys(); 
const bobSessionKeys = Bob.generateSessionKeys();

const aliceSharedSessionKeys = Alice.generateSharedSessionKeysInitial(
  aliceSessionKeys.publicKey,
  aliceSessionKeys.privateKey,
  bobSessionKeys.publicKey
); // {receiveKey, sendKey}

const bobSharedSessionKeys = Bob.generateSharedSessionKeysResponse(
  bobSessionKeys.publicKey,
  bobSessionKeys.privateKey,
  aliceSessionKeys.publicKey
); // {receiveKey, sendKey}

```

### Performing Prism Layer Encryption

Prism chat offerers E2E, decentralized and anonymous encryption. We use [libsodium](https://doc.libsodium.org/) functions to perform several encryption layers which is the core of Prism Chat. Below is an example of how to perform each layer of encryption in sequence and decrypt it expecting session keys have been generated and exchanged.

#### Encryption

``` javascript
const Alice = new Prism(publicKey, privateKey);
await Alice.init();

const message = {
  message: "Hello World!"
}

const layer1Up = Alice.prismEncrypt_Layer1(
  message,
  AliceBobSessionKeys.sendKey
);

const layer2Up = Alice.prismEncrypt_Layer2(
  'M',
  1,
  layer1Up.nonce,
  layer1Up.cypherText,
  Bob.IdentityKeys.public
);

const layer3Up = Alice.prismEncrypt_Layer3(layer2Up.nonce, layer2Up.cypherText);

const encryptedString = Alice.prismEncrypt_Layer4(
  layer3Up.key,
  layer3Up.nonce,
  layer3Up.cypherText,
  Bob.IdentityKeys.public
); // "Encrypted String"
```

#### Decryption

``` javascript
const Bob = new Prism(publicKey, privateKey);
await Bob.init();

const layer4Down = Bob.prismDecrypt_Layer4(encryptedString);

const layer3Down = Bob.prismDecrypt_Layer3(
  layer4Down.nonce,
  layer4Down.key,
  layer4Down.cypherText
);

const layer2Down = Bob.prismDecrypt_Layer2(
  layer3Down.nonce,
  layer3Down.cypherText,
  layer3Down.from
);

const decryptedData = Bob.prismDecrypt_Layer1(
  layer2Down.nonce,
  layer2Down.cypherText,
  AliceBobSessionKeys.receiveKey
); // {message: "Hello World!"}
```

### Notes

Some useful notes when working with prismchat-lib.

* All base64 encoding is done using the ```URLSAFE_NO_PADDING``` variant. This is the output and expected input of any base64 encoding.
