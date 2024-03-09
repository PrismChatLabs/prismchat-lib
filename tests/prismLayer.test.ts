/**
 * Tests for the prism layer encryption system.
*/

import { Prism } from '../src/main';

let Alice: any = null;
let Bob: any = null;

let aliceSession = {
	pk: null,
	sk: null,
	rx: null,
	tx: null,
	cnt: 0
}

let bobSession = {
	pk: null,
	sk: null,
	rx: null,
	tx: null,
	cnt: 0
}

beforeEach(async () => {
	// Generate Alice
	Alice = new Prism();
	await Alice.init();
	Alice.generateIdentityKeys();

	// Generate Bob
	Bob = new Prism();
	await Bob.init();
	Bob.generateIdentityKeys();

	// Perform key exchange and generate session keys for Alice and Bob
	let {pk: Apk, sk: Ask} = Alice.generateSessionKeys();
	aliceSession.pk = Apk;
	aliceSession.sk = Ask;

	let {pk: Bpk, sk: Bsk} = Bob.generateSessionKeys();
	bobSession.pk = Bpk;
	bobSession.sk = Bsk;

	let {rx: Brx, tx: Btx} = Bob.generateSharedSessionKeysRequest(bobSession.pk, bobSession.sk, aliceSession.pk);
	bobSession.rx = Brx;
	bobSession.tx = Btx;

	let {rx: Arx, tx: Atx} = Alice.generateSharedSessionKeysResponse(aliceSession.pk, aliceSession.sk, bobSession.pk);
	aliceSession.rx = Arx;
	aliceSession.tx = Atx;
});

afterEach(async () => {
	Alice = null;
	Bob = null;
	aliceSession = {
		pk: null,
		sk: null,
		rx: null,
		tx: null,
		cnt: 0
	}
	
	bobSession = {
		pk: null,
		sk: null,
		rx: null,
		tx: null,
		cnt: 0
	}
});

test('Layer0', async () => {
	let data = {
		message: 'Hello World!',
	};

	aliceSession.cnt ++;
	let alice_tx_subkey = Alice.sessionKeyDerivation(aliceSession.tx, aliceSession.cnt);
	let {nonce, cipher}: any = Alice.layer0_encrypt(data, alice_tx_subkey);

	let bob_rx_subkey = Bob.sessionKeyDerivation(bobSession.rx, aliceSession.cnt);
	let decryptedData: any = Bob.layer0_decrypt(cipher, bob_rx_subkey, nonce);

	expect(decryptedData).toStrictEqual(data);
});

test('Layer1', async () => {
	let data = {
		message: 'Hello World!',
	};

	// Layer 0 encrypt (Alice)
	aliceSession.cnt ++;

	let alice_tx_subkey = Alice.sessionKeyDerivation(aliceSession.tx, aliceSession.cnt);
	let layer0_encrypt: any = Alice.layer0_encrypt(data, alice_tx_subkey);

	// Layer 1 encrypt (Alice)
	let layer1_encrypt: any = Alice.layer1_encrypt(layer0_encrypt.cipher, layer0_encrypt.nonce, Bob.Ipk, "m", aliceSession.cnt);

	// layer 1 decrypt (Bob)
	let layer1_decrypt: any = Bob.layer1_decrypt(layer1_encrypt.cipher, layer1_encrypt.nonce, Alice.Ipk);

	// layer 0 decrypt (Bob)
	let bob_rx_subkey = Bob.sessionKeyDerivation(bobSession.rx, layer1_decrypt.cnt);
	let decryptedData: any = Bob.layer0_decrypt(layer1_decrypt.data, bob_rx_subkey, layer1_decrypt.nonce);

	expect(decryptedData).toStrictEqual(data);
});

test('Layer2', async () => {
	let data = {
		message: 'Hello World!',
	};

	// Layer 0 encrypt (Alice)
	aliceSession.cnt ++;

	let alice_tx_subkey = Alice.sessionKeyDerivation(aliceSession.tx, aliceSession.cnt);
	let layer0_encrypt: any = Alice.layer0_encrypt(data, alice_tx_subkey);

	// Layer 1 encrypt (Alice)
	let layer1_encrypt: any = Alice.layer1_encrypt(layer0_encrypt.cipher, layer0_encrypt.nonce, Bob.Ipk, "m", aliceSession.cnt);

	// Layer 2 encrypt (Alice)
	let layer2_encrypt: any = Alice.layer2_encrypt(layer1_encrypt.cipher, layer1_encrypt.nonce);

	// layer 2 decrypt (Bob)
	let layer2_decrypt: any = Bob.layer2_decrypt(layer2_encrypt.cipher, layer2_encrypt.key, layer2_encrypt.nonce);

	// layer 1 decrypt (Bob)
	let layer1_decrypt: any = Bob.layer1_decrypt(layer2_decrypt.data, layer2_decrypt.nonce, Alice.Ipk);

	// layer 0 decrypt (Bob)
	let bob_rx_subkey = Bob.sessionKeyDerivation(bobSession.rx, layer1_decrypt.cnt);
	let decryptedData: any = Bob.layer0_decrypt(layer1_decrypt.data, bob_rx_subkey, layer1_decrypt.nonce);

	expect(decryptedData).toStrictEqual(data);
});

test('Layer3', async () => {
	let data = {
		message: 'Hello World!',
	};

	// Layer 0 encrypt (Alice)
	aliceSession.cnt ++;

	let alice_tx_subkey = Alice.sessionKeyDerivation(aliceSession.tx, aliceSession.cnt);
	let layer0_encrypt: any = Alice.layer0_encrypt(data, alice_tx_subkey);

	// Layer 1 encrypt (Alice)
	let layer1_encrypt: any = Alice.layer1_encrypt(layer0_encrypt.cipher, layer0_encrypt.nonce, Bob.Ipk, "m", aliceSession.cnt);

	// Layer 2 encrypt (Alice)
	let layer2_encrypt: any = Alice.layer2_encrypt(layer1_encrypt.cipher, layer1_encrypt.nonce);

	// Layer 3 encrypt (Alice)
	let layer3_encrypt: any = Alice.layer3_encrypt(layer2_encrypt.cipher, layer2_encrypt.nonce, layer2_encrypt.key, Bob.Ipk);

	// layer 3 decrypt (Bob)
	let layer3_decrypt: any = Bob.layer3_decrypt(layer3_encrypt.keyCipher, layer3_encrypt.dataCipher);

	// layer 2 decrypt (Bob)
	let layer2_decrypt: any = Bob.layer2_decrypt(layer3_decrypt.cipher, layer3_decrypt.key, layer3_decrypt.nonce);

	// layer 1 decrypt (Bob)
	let layer1_decrypt: any = Bob.layer1_decrypt(layer2_decrypt.data, layer2_decrypt.nonce, Alice.Ipk);

	// layer 0 decrypt (Bob)
	let bob_rx_subkey = Bob.sessionKeyDerivation(bobSession.rx, layer1_decrypt.cnt);
	let decryptedData: any = Bob.layer0_decrypt(layer1_decrypt.data, bob_rx_subkey, layer1_decrypt.nonce);

	expect(decryptedData).toStrictEqual(data);
});

test('Layer FULL', async () => {
	let data = {
		message: 'Hello World!',
	};

	// Layer 0 encrypt (Alice)
	aliceSession.cnt ++;

	let alice_tx_subkey = Alice.sessionKeyDerivation(aliceSession.tx, aliceSession.cnt);
	let {keyCipher, dataCipher}: any = Alice.layer_encrypt(data, alice_tx_subkey, Bob.Ipk, 'm', aliceSession.cnt);

	// layer 1 decrypt (Bob)
	let layer1_decrypt: any = Bob.layer_decrypt(keyCipher, dataCipher);

	// layer 0 decrypt (Bob)
	let bob_rx_subkey = Bob.sessionKeyDerivation(bobSession.rx, layer1_decrypt.cnt);
	let decryptedData: any = Bob.layer0_decrypt(layer1_decrypt.data, bob_rx_subkey, layer1_decrypt.nonce);

	expect(decryptedData).toStrictEqual(data);
});
