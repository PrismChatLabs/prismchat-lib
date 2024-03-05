# Prism Lib

Checkout our **[live web demo!](https://app-demo.prism.chat/)**

The Prism Chat Library for E2E, anonymous and decentralized communication built on [libsodium](https://doc.libsodium.org/). We have used [libsodium](https://doc.libsodium.org/) as the base for all of our cryptographic operations as it gives and easy to use interface as well as known security. This allows us to focus on the higher level cryptographic logic that makes Prism what it is.

## Usage

PrismChat-lib has been packaged in a node module for easy deployment and is essentially a single class. This class stores the state of the users Identity Keys which are used for most cryptographic operations. PrismChat-lib also exposes all of the pure functions included in [libsodium](https://doc.libsodium.org/). This approach allows us to easily perform Prism specific encryption operations utalizing its own state, or any pure functions of [libsodium](https://doc.libsodium.org/), not relying on any state.

### Instantiation

When creating a new Prism instance it can be created with or without identity keys, but they are required by the class to perform cryptographic operations. You can include them at instantiation as parameters to the constructor or create them after instantiation with a function that will both update the state of the instance and return the string values.

``` javascript
const Alice = new Prism();
await Alice.init();

// Function will both update state and return values
const {Ipk, Isk} = Alice.generateIdentityKeys(); 
```

``` javascript
const Alice = new Prism(Ipk, Ik);
await Alice.init();

// Access Identity Key state after instantiation
Alice.Ipk;
Alice.Isk;
```

### Accessing the sodium instance

You can access the sodium instance and all of its pure functions by accessing the ```sodium``` property of a prism object. Below is an example of how to access the base64 encoding function of [libsodium](https://doc.libsodium.org/). It could be noted that all base64 encoding for Prism is done with the ```URLSAFE_NO_PADDING``` variant. There is also a `toBase64` and `frombase64` function that automatically performs base64 conversions using `URLSAFE_NO_PADDING` in the prism class.

``` javascript
const Alice = new Prism(Public, Private);
await Alice.init();

const base64EncodedString = Alice.sodium.to_base64(
  "Hello World!",
  Alice.sodium.base64_variants.URLSAFE_NO_PADDING
);
```

### Performing Prism key exchange

When chatting with Prism we use a key exchange method to generate session keys for each specific chat you are engaged in. This is done by generating random and unique session keys independently, exchanging the public key of the session, and then independently calculating the same shared send and recieve keys. After each message the keys should be modified via the derivation function to ensure forward security. Below is an example of that key exchange.

``` javascript
const Alice = new Prism();
await Alice.init();
Alice.generateIdentityKeys();

const Bob = new Prism();
await Bob.init();
Bob.generateIdentityKeys();

// Generate session master keys and send pk to bob
const aliceSessionKeys = Alice.generateSessionKeys(); // {pk, sk}

// Bob recieves Alice pk and generates his own master keys and sends Alice his pk
const bobSessionKeys = Bob.generateSessionKeys(); // {pk, sk}

// Bob generates his send and recieve keys (if you recieve the request you use the generateSharedSessionKeysRequest method)
const bobSessionKeys = Bob.generateSharedSessionKeysRequest(Bob_pk, Bob_sk, Alice_pk); // {rx, tx}

// Alice now recieving a responce from bob with his session pk she dies the same (if you made the initial request and recieve a responce use the generateSharedSessionKeysResponse method)
const bobSessionKeys = Bob.generateSharedSessionKeysRequest(Bob_pk, Bob_sk, Alice_pk); // {rx, tx}
```

### Performing Prism Layer Encryption

Prism chat offerers E2E, decentralized and anonymous encryption. We use [libsodium](https://doc.libsodium.org/) functions to perform several encryption layers which is the core of Prism Chat. Below is an example of how to perform each layer of encryption in sequence and decrypt it expecting session keys have been generated and exchanged.

#### Encryption

``` javascript
const Alice = new Prism(publicKey, privateKey);
await Alice.init();

let data = {
  message: 'Hello World!',
};

// Generate subkey from the session tx and perform layer0 encryption
let alice_tx_subkey = Alice.sessionKeyDerivation(aliceSession.tx, aliceSession.cnt);
let layer0_encrypt: any = Alice.layer0_encrypt(data, alice_tx_subkey);

// Layer 1 encrypt
let layer1_encrypt: any = Alice.layer1_encrypt(layer0_encrypt.cipher, layer0_encrypt.nonce, Bob.Ipk, "m", aliceSession.cnt);

// Layer 2 encrypt
let layer2_encrypt: any = Alice.layer2_encrypt(layer1_encrypt.cipher, layer1_encrypt.nonce, Bob.Ipk);

// layer2_encrypt is the final layer and can be sent to Bob for decryption now.
```

#### Decryption

``` javascript
const Bob = new Prism(publicKey, privateKey);
await Bob.init();

// layer 2 decrypt
let layer2_decrypt: any = Bob.layer2_decrypt(layer2_encrypt);

// layer 1 decrypt
let layer1_decrypt: any = Bob.layer1_decrypt(layer2_decrypt.data, layer2_decrypt.nonce, Alice.Ipk);

// Generate subkey from the session rx and perform layer0 encryption
let bob_rx_subkey = Bob.sessionKeyDerivation(bobSession.rx, layer1_decrypt.cnt);
let decryptedData: any = Bob.layer0_decrypt(layer1_decrypt.data, bob_rx_subkey, layer1_decrypt.nonce);

// Now bob has recieved a decrypted and parsed json object.
```

### Notes

Some useful notes when working with prismchat-lib.

* All base64 encoding is done using the ```URLSAFE_NO_PADDING``` variant. This is the output and expected input of any base64 encoding.
