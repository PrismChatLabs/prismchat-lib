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

test('Symmetric Encrypt and Decrypt', async () => {
	let data = {
		message: 'Hello World!',
	};

	let encryptedData: any = Alice.symmetricEncrypt(data);
	let decryptedData: any = Bob.symmetricDecrypt(
		encryptedData.key,
		encryptedData.nonce,
		encryptedData.cypherText
	);

	expect(decryptedData).toStrictEqual(data);
});

test('Public Encrypt and Decrypt', async () => {
	let dataObj = {
		message: 'Hello World!',
	};

	let cypherText = Alice.publicEncrypt(dataObj, Bob.IdentityKeys.public);
	let text = Bob.publicDecrypt(cypherText);

	expect(text).toStrictEqual(dataObj);
});

test('Generate Shared Session Keys', async () => {
	let aliceSessionKeys = Alice.generateSessionKeys();
	let bobSessionKeys = Bob.generateSessionKeys();

	let aliceSharedSessionKeys = Alice.generateSharedSessionKeysInitial(
		aliceSessionKeys.publicKey,
		aliceSessionKeys.privateKey,
		bobSessionKeys.publicKey
	);

	let bobSharedSessionKeys = Bob.generateSharedSessionKeysResponse(
		bobSessionKeys.publicKey,
		bobSessionKeys.privateKey,
		aliceSessionKeys.publicKey
	);

	expect(bobSharedSessionKeys.sendKey).toStrictEqual(
		aliceSharedSessionKeys.receiveKey
	);
	expect(aliceSharedSessionKeys.sendKey).toStrictEqual(
		bobSharedSessionKeys.receiveKey
	);
});

test('Key Exchange & Derivation', async () => {
	let aliceSessionKeys = Alice.generateSessionKeys();
	let bobSessionKeys = Bob.generateSessionKeys();

	let aliceSharedSessionKeys = Alice.generateSharedSessionKeysInitial(
		aliceSessionKeys.publicKey,
		aliceSessionKeys.privateKey,
		bobSessionKeys.publicKey
	);

	let bobSharedSessionKeys = Bob.generateSharedSessionKeysResponse(
		bobSessionKeys.publicKey,
		bobSessionKeys.privateKey,
		aliceSessionKeys.publicKey
	);

	let aliceSharedSessionSendKeyDerived = Alice.sessionKeyDerivation(
		aliceSharedSessionKeys.sendKey,
		1
	);
	let bobSharedSessionReceiveKeyDerived = Bob.sessionKeyDerivation(
		bobSharedSessionKeys.receiveKey,
		1
	);

	let bobSharedSessionSendKeyDerived = Bob.sessionKeyDerivation(
		bobSharedSessionKeys.sendKey,
		1
	);
	let aliceSharedSessionReceiveKeyDerived = Alice.sessionKeyDerivation(
		aliceSharedSessionKeys.receiveKey,
		1
	);

	expect(aliceSharedSessionSendKeyDerived).toStrictEqual(
		bobSharedSessionReceiveKeyDerived
	);
	expect(bobSharedSessionSendKeyDerived).toStrictEqual(
		aliceSharedSessionReceiveKeyDerived
	);

	expect(aliceSharedSessionKeys.sendKey).not.toStrictEqual(
		bobSharedSessionReceiveKeyDerived
	);
	expect(aliceSharedSessionKeys.receiveKey).not.toStrictEqual(
		aliceSharedSessionReceiveKeyDerived
	);
	expect(bobSharedSessionKeys.sendKey).not.toStrictEqual(
		bobSharedSessionReceiveKeyDerived
	);
	expect(bobSharedSessionKeys.receiveKey).not.toStrictEqual(
		aliceSharedSessionReceiveKeyDerived
	);
});

test('Prism Object Encrypt & Decrypt', async () => {
	let aliceSessionKeys = Alice.generateSessionKeys();
	let bobSessionKeys = Bob.generateSessionKeys();

	let aliceSharedSessionKeys = Alice.generateSharedSessionKeysInitial(
		aliceSessionKeys.publicKey,
		aliceSessionKeys.privateKey,
		bobSessionKeys.publicKey
	);

	let bobSharedSessionKeys = Bob.generateSharedSessionKeysResponse(
		bobSessionKeys.publicKey,
		bobSessionKeys.privateKey,
		aliceSessionKeys.publicKey
	);

	let data = {
		message:
			'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam id felis cursus, porta velit sit amet, vestibulum lacus. Quisque mi odio, venenatis at libero eu, luctus vestibulum odio. Aliquam erat volutpat. Maecenas ac dignissim dui. Nullam turpis nisl, tempor in tempus ut, tincidunt ac ex. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Nam et sem rutrum ante pharetra condimentum ut ut velit. Duis mattis lacus lectus, nec lacinia sem cursus id. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Integer a pellentesque nisi. Sed accumsan lectus in est tristique viverra. Duis ornare volutpat mollis. Proin at porta justo. Maecenas scelerisque sagittis malesuada. Pellentesque condimentum ultrices diam. Duis gravida pellentesque convallis. In iaculis nisl pellentesque, cursus ex et, congue arcu. Fusce malesuada tempor lorem quis hendrerit. Sed suscipit tincidunt massa id rutrum. Curabitur gravida, lorem vel imperdiet consectetur, risus erat vestibulum risus, quis cursus orci neque in orci. Sed convallis, elit eget vehicula scelerisque, nunc erat facilisis libero, ac eleifend ligula metus nec est. Aliquam vehicula quam enim, et sodales turpis lacinia sit amet. Vestibulum nec quam venenatis, viverra purus eget, sollicitudin eros. Praesent lacus metus, tristique non ex ac, pulvinar bibendum neque. Etiam gravida dapibus nisi sit amet sollicitudin. Suspendisse elementum commodo suscipit. Etiam vulputate consectetur dapibus. Cras vel egestas est, faucibus facilisis libero. Etiam eu pharetra erat. Duis vel rutrum ipsum. In id elementum metus. Nunc id leo eu turpis aliquet cursus. Pellentesque eu dui ante. Nulla vitae massa magna. Nulla fermentum condimentum scelerisque. Vivamus nec lacus sed mi faucibus dictum at quis urna. Aliquam bibendum quam ut laoreet aliquam. Maecenas non posuere urna. Nam feugiat enim feugiat dapibus congue. Aliquam urna metus, blandit at consectetur sed, feugiat eget tellus. Pellentesque tristique augue in erat aliquam sollicitudin. Proin id rutrum erat, ut faucibus dui. Cras a velit felis. Sed dictum quam ante, fringilla luctus leo pharetra euismod. Vestibulum dignissim nulla at dui ornare vestibulum. Phasellus mollis odio justo, consectetur porttitor ante pellentesque in. Duis vitae rutrum justo. Donec a arcu in quam auctor dignissim eget luctus ligula. Fusce viverra dapibus suscipit. Pellentesque ultricies ipsum neque, ut lacinia ante aliquet aliquet. Maecenas et mauris augue. Vestibulum ut iaculis nisl, at euismod nulla. Pellentesque finibus, mi vel consequat feugiat, massa urna accumsan quam, sit amet rutrum eros purus ac velit. Phasellus non arcu et tortor fringilla dapibus. Quisque a tortor ipsum. Aliquam erat volutpat. Donec tincidunt, elit sit amet rutrum volutpat, neque ligula interdum tortor, sit amet consectetur tellus arcu id dui.',
	};

	// Alice encryption
	let layer1Up = Alice.prismEncrypt_Layer1(
		data,
		aliceSharedSessionKeys.sendKey
	);
	let layer2Up = Alice.prismEncrypt_Layer2(
		'M',
		1,
		layer1Up.nonce,
		layer1Up.cypherText,
		Bob.IdentityKeys.public
	);
	let layer3Up = Alice.prismEncrypt_Layer3(layer2Up.nonce, layer2Up.cypherText);
	let encryptedData = Alice.prismEncrypt_Layer4(
		layer3Up.key,
		layer3Up.nonce,
		layer3Up.cypherText,
		Bob.IdentityKeys.public
	);

	// Bob decryption
	let layer4Down = Bob.prismDecrypt_Layer4(encryptedData);
	let layer3Down = Bob.prismDecrypt_Layer3(
		layer4Down.nonce,
		layer4Down.key,
		layer4Down.cypherText
	);
	let layer2Down = Bob.prismDecrypt_Layer2(
		layer3Down.nonce,
		layer3Down.cypherText,
		layer3Down.from
	);
	let decryptedData = Bob.prismDecrypt_Layer1(
		layer2Down.nonce,
		layer2Down.cypherText,
		bobSharedSessionKeys.receiveKey
	);

	expect(decryptedData).toStrictEqual(data);
});
