import { Prism } from '../src/main';

let Alice: any = null;
let aliceSessionKeys: any = null;
let aliceSharedSessionKeys: any = null;

let Bob: any = null;
let bobSessionKeys: any = null;
let bobSharedSessionKeys: any = null;

let expectedData: any = null;

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
});

afterEach(async () => {
	Alice = null;
	aliceSessionKeys = null;
	aliceSharedSessionKeys = null;

	Bob = null;
	bobSessionKeys = null;
	bobSharedSessionKeys = null;
});

test('Layer1 Encrypt', async () => {
	const layer1encrypt = Alice.prismEncrypt_Layer1(
		expectedData,
		aliceSharedSessionKeys.sendKey
	);
	const layer1decrypt = Bob.prismDecrypt_Layer1(
		layer1encrypt.nonce,
		layer1encrypt.cypherText,
		bobSharedSessionKeys.receiveKey
	);

	expect(layer1decrypt).toStrictEqual(expectedData);
});

test('Layer2 Encrypt', async () => {
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

	expect(layer2encrypt && typeof layer2encrypt['nonce'] == 'string').toBe(true);
	expect(layer2encrypt && typeof layer2encrypt['cypherText'] == 'string').toBe(
		true
	);
});

test('Layer3 Encrypt', async () => {
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

	expect(layer3encrypt && typeof layer3encrypt['nonce'] == 'string').toBe(true);
	expect(layer3encrypt && typeof layer3encrypt['key'] == 'string').toBe(true);
	expect(layer3encrypt && typeof layer3encrypt['cypherText'] == 'string').toBe(
		true
	);
});

test('Layer4 Encrypt', async () => {
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

	const layer4encrypt = Alice.prismEncrypt_Layer4(
		layer3encrypt.key,
		layer3encrypt.nonce,
		layer3encrypt.cypherText,
		Bob.IdentityKeys.public
	);

	expect(layer4encrypt).not.toBeNull();
});
