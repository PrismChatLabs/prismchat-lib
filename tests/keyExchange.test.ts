/**
 * Key exchange tests.
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

test('Perform key exchange', async () => {

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

	expect(aliceSession.pk).not.toStrictEqual(bobSession.pk);
	expect(aliceSession.pk).not.toStrictEqual(bobSession.pk);
	expect(aliceSession.rx).toStrictEqual(bobSession.tx);
	expect(aliceSession.tx).toStrictEqual(bobSession.rx);
});
