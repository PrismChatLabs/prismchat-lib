/**
 * Unit tests for the main encryption methods, not including the layered encryption methods.
*/

import { Prism } from '../src/main';

let Alice: any = null;
let Bob: any = null;

beforeEach(async () => {
	// Generate Alice
	Alice = new Prism();
	await Alice.init();
	Alice.generateIdentityKeys();

	// Generate Bob
	Bob = new Prism();
	await Bob.init();
	Bob.generateIdentityKeys();
});

afterEach(async () => {
	Alice = null;
	Bob = null;
});

test('Unauthenticated asymetric encryption', async () => {
	let data = {
		message: 'Hello World!',
	};

	let encryptedData: any = Alice.unauthenticatedAsymetricEncrypt(data, Bob.Ipk);
	let decryptedData: any = Bob.unauthenticatedAsymetricDecrypt(encryptedData);

	expect(decryptedData).toStrictEqual(data);
});

test('Authenticated asymetric encryption', async () => {
	let data = {
		message: 'Hello World!',
	};

	let {nonce, cipher}: any = Alice.authenticatedAsymetricEncrypt(data, Bob.Ipk);
	let decryptedData: any = Bob.authenticatedAsymetricDecrypt(cipher, nonce, Alice.Ipk);

	expect(decryptedData).toStrictEqual(data);
});

test('Symetric encryption', async () => {
	let data = {
		message: 'Hello World!',
	};

	let {key, nonce, cipher}: any = Alice.symmetricEncrypt(data);
	let decryptedData: any = Bob.symmetricDecrypt(cipher, key, nonce);

	expect(decryptedData).toStrictEqual(data);
});
