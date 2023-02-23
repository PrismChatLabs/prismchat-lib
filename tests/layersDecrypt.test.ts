import { Prism } from '../src/main';

let Alice: any = null;
let aliceSessionKeys: any = null;
let aliceSharedSessionKeys: any = null;

let Bob: any = null;
let bobSessionKeys: any = null;
let bobSharedSessionKeys: any = null;

let expectedData: any = null;
let aliceEncrypted: any = null;

beforeEach(async () => {
	// Generate Alice
	Alice = new Prism();
	await Alice.init();
	Alice.generateIdentityKeys();

	// Generate Bob
	Bob = new Prism();
	await Bob.init();
	Bob.generateIdentityKeys();

	aliceSessionKeys = Alice.generateSessionKeys();
	bobSessionKeys = Bob.generateSessionKeys();

	aliceSharedSessionKeys = Alice.generateSharedSessionKeysInitial(
		aliceSessionKeys.publicKey,
		aliceSessionKeys.privateKey,
		bobSessionKeys.publicKey
	);

	bobSharedSessionKeys = Bob.generateSharedSessionKeysResponse(
		bobSessionKeys.publicKey,
		bobSessionKeys.privateKey,
		aliceSessionKeys.publicKey
	);

	expectedData = {
		message: 'Hello World!',
	};

	const layer1encrypt = Alice.prismEncrypt_Layer1(
		expectedData,
		aliceSharedSessionKeys.sendKey
	);

	const layer2encrypt = Alice.prismEncrypt_Layer2(
		'M',
		1,
		layer1encrypt.nonce,
		layer1encrypt.cypherText,
		Bob.IdentityKeys.public
	);

	const layer3encrypt = Alice.prismEncrypt_Layer3(
		layer2encrypt.nonce,
		layer2encrypt.cypherText
	);

	aliceEncrypted = Alice.prismEncrypt_Layer4(
		layer3encrypt.key,
		layer3encrypt.nonce,
		layer3encrypt.cypherText,
		Bob.IdentityKeys.public
	);
});

afterEach(async () => {
	Alice = null;
	aliceSessionKeys = null;
	aliceSharedSessionKeys = null;

	Bob = null;
	bobSessionKeys = null;
	bobSharedSessionKeys = null;

	aliceEncrypted = null;
});

test('Layer4 Decrypt', async () => {
	let layer4decrypt = Bob.prismDecrypt_Layer4(aliceEncrypted);
	expect(layer4decrypt && typeof layer4decrypt['nonce'] == 'string').toBe(true);
	expect(layer4decrypt && typeof layer4decrypt['key'] == 'string').toBe(true);
	expect(layer4decrypt && typeof layer4decrypt['cypherText'] == 'string').toBe(
		true
	);
});

test('Layer3 Decrypt', async () => {
	let layer4decrypt = Bob.prismDecrypt_Layer4(aliceEncrypted);
	let layer3decrypt = Bob.prismDecrypt_Layer3(
		layer4decrypt.nonce,
		layer4decrypt.key,
		layer4decrypt.cypherText
	);

	expect(layer3decrypt && typeof layer3decrypt['from'] == 'string').toBe(true);
	expect(layer3decrypt && typeof layer3decrypt['nonce'] == 'string').toBe(true);
	expect(layer3decrypt && typeof layer3decrypt['cypherText'] == 'string').toBe(
		true
	);
	expect(layer3decrypt['from']).toStrictEqual(Alice.IdentityKeys.public);
});

test('Layer2 Decrypt', async () => {
	let layer4decrypt = Bob.prismDecrypt_Layer4(aliceEncrypted);
	let layer3decrypt = Bob.prismDecrypt_Layer3(
		layer4decrypt.nonce,
		layer4decrypt.key,
		layer4decrypt.cypherText
	);
	let layer2decrypt = Bob.prismDecrypt_Layer2(
		layer3decrypt.nonce,
		layer3decrypt.cypherText,
		layer3decrypt.from
	);
	expect(layer2decrypt && typeof layer2decrypt['type'] == 'string').toBe(true);
	expect(layer2decrypt && typeof layer2decrypt['count'] == 'number').toBe(true);
	expect(layer2decrypt && typeof layer2decrypt['date'] == 'number').toBe(true);
	expect(layer2decrypt && typeof layer2decrypt['nonce'] == 'string').toBe(true);
	expect(layer2decrypt && typeof layer2decrypt['cypherText'] == 'string').toBe(
		true
	);
});

test('Layer1 Decrypt', async () => {
	let layer4decrypt = Bob.prismDecrypt_Layer4(aliceEncrypted);
	let layer3decrypt = Bob.prismDecrypt_Layer3(
		layer4decrypt.nonce,
		layer4decrypt.key,
		layer4decrypt.cypherText
	);
	let layer2decrypt = Bob.prismDecrypt_Layer2(
		layer3decrypt.nonce,
		layer3decrypt.cypherText,
		layer3decrypt.from
	);
	let decryptedData = Bob.prismDecrypt_Layer1(
		layer2decrypt.nonce,
		layer2decrypt.cypherText,
		bobSharedSessionKeys.receiveKey
	);
	expect(decryptedData).toStrictEqual(expectedData);
});
