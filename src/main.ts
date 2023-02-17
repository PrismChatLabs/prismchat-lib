const _sodium = require('libsodium-wrappers');

export class Prism {
	private _IdentityKeys: any;
	private sodium: any;

	constructor(publicIdentityKey: any = null, privateIdentityKey: any = null) {
		this._IdentityKeys = {
			public: publicIdentityKey,
			private: privateIdentityKey,
		};
	}

	async init() {
		await _sodium.ready;
		this.sodium = _sodium;
	}

	public get IdentityKeys() {
		return this._IdentityKeys;
	}

	public generateIdentityKeys(): any {
		let { publicKey, privateKey } = this.sodium.crypto_box_keypair();
		this._IdentityKeys.public = this.sodium.to_base64(publicKey);
		this._IdentityKeys.private = this.sodium.to_base64(privateKey);
		return this.IdentityKeys;
	}

	public publicEncrypt(message: any, recipientPublicKey: any): any {
		let cypherText = this.sodium.crypto_box_seal(
			JSON.stringify(message),
			this.sodium.from_base64(recipientPublicKey)
		);
		return this.sodium.to_base64(cypherText);
	}

	public publicDecrypt(cypherText: any): any {
		let plainText = this.sodium.crypto_box_seal_open(
			this.sodium.from_base64(cypherText),
			this.sodium.from_base64(this.IdentityKeys.public),
			this.sodium.from_base64(this.IdentityKeys.private)
		);
		return JSON.parse(this.sodium.to_string(plainText));
	}

	public symmetricEncrypt(payloadObj: any, key: any = null): any {
		if (key == null) {
			key = this.sodium.crypto_aead_chacha20poly1305_keygen();
		} else {
			key = this.sodium.from_base64(key);
		}

		let nonce: any = this.sodium.randombytes_buf(
			this.sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
		);

		let cypherText: any =
			this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
				JSON.stringify(payloadObj),
				null,
				null,
				nonce,
				key
			);

		return {
			key: this.sodium.to_base64(key),
			nonce: this.sodium.to_base64(nonce),
			cypherText: this.sodium.to_base64(cypherText),
		};
	}

	public symmetricDecrypt(key: any, nonce: any, cypherText: any): any {
		let message: any = this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
			null,
			this.sodium.from_base64(cypherText),
			null,
			this.sodium.from_base64(nonce),
			this.sodium.from_base64(key)
		);
		return JSON.parse(this.sodium.to_string(message));
	}

	public generateSessionKeys(): any {
		let { publicKey, privateKey }: any = this.sodium.crypto_kx_keypair();
		return {
			publicKey: this.sodium.to_base64(publicKey),
			privateKey: this.sodium.to_base64(privateKey),
		};
	}

	public generateSharedSessionKeysInitial(
		sessionPublicKey: any,
		sessionPrivateKey: any,
		partnerPublicKey: any
	): any {
		let { sharedRx, sharedTx }: any = this.sodium.crypto_kx_client_session_keys(
			this.sodium.from_base64(sessionPublicKey),
			this.sodium.from_base64(sessionPrivateKey),
			this.sodium.from_base64(partnerPublicKey)
		);

		return {
			receiveKey: this.sodium.to_base64(sharedRx),
			sendKey: this.sodium.to_base64(sharedTx),
		};
	}

	public generateSharedSessionKeysResponse(
		sessionPublicKey: any,
		sessionPrivateKey: any,
		partnerPublicKey: any
	): any {
		let { sharedRx, sharedTx }: any = this.sodium.crypto_kx_server_session_keys(
			this.sodium.from_base64(sessionPublicKey),
			this.sodium.from_base64(sessionPrivateKey),
			this.sodium.from_base64(partnerPublicKey)
		);

		return {
			receiveKey: this.sodium.to_base64(sharedRx),
			sendKey: this.sodium.to_base64(sharedTx),
		};
	}

	public sessionKeyDerivation(
		key: any,
		count: number,
		context: String = '___PRISM'
	): any {
		let derivedKey = this.sodium.crypto_kdf_derive_from_key(
			this.sodium.crypto_kdf_KEYBYTES,
			count,
			context,
			this.sodium.from_base64(key)
		);

		return this.sodium.to_base64(derivedKey);
	}

	public encryptPrismObject(
		data: any,
		sharedSessionKeySend: any,
		recipientPublicKey: any
	): any {
		// Layer 1
		// Encrypt data object symmetrically if type is MESSAGE.
		let layer_1_cypherText: any = this.symmetricEncrypt(
			data,
			sharedSessionKeySend
		);

		// Layer 2
		// Encrypt payload generated in layer 1 with crypto_secret_box to verify identity and encrypt sensitive data.
		let layer_2_nonce = this.sodium.randombytes_buf(
			this.sodium.crypto_box_NONCEBYTES
		);

		let layer_2_cypherText: any = this.sodium.crypto_box_easy(
			JSON.stringify({
				type: 'M',
				date: Date.now(),
				nonce: layer_1_cypherText.nonce,
				data: layer_1_cypherText.cypherText,
			}),
			layer_2_nonce,
			this.sodium.from_base64(recipientPublicKey),
			this.sodium.from_base64(this.IdentityKeys.private)
		);

		// Layer 3
		// Encrypt payload generated in layer 2 with a random symmetric key.
		let layer_3_cypherText: any = this.symmetricEncrypt({
			from: this.IdentityKeys.public,
			nonce: this.sodium.to_base64(layer_2_nonce),
			payload: this.sodium.to_base64(layer_2_cypherText),
		});

		// Layer 4
		// Encrypt layer 3 obj with recipients public key.
		let layer_4_cypher: any = this.publicEncrypt(
			{
				key: layer_3_cypherText.key,
				nonce: layer_3_cypherText.nonce,
			},
			recipientPublicKey
		);

		return `${layer_4_cypher}:${layer_3_cypherText.cypherText}`;
	}

	public decryptPrismObject(
		dataObj: String,
		sharedSessionKeyReceive: any
	): any {
		let [layer_4_cypher, layer_3_cypherTextCypherText] = dataObj.split(':');

		let layer_4_dataObj = this.publicDecrypt(layer_4_cypher);
		let layer_3_dataObj = this.symmetricDecrypt(
			layer_4_dataObj.key,
			layer_4_dataObj.nonce,
			layer_3_cypherTextCypherText
		);
		let layer_2_dataObj = JSON.parse(
			this.sodium.to_string(
				this.sodium.crypto_box_open_easy(
					this.sodium.from_base64(layer_3_dataObj.payload),
					this.sodium.from_base64(layer_3_dataObj.nonce),
					this.sodium.from_base64(layer_3_dataObj.from),
					this.sodium.from_base64(this.IdentityKeys.private)
				)
			)
		);
		let data = this.symmetricDecrypt(
			sharedSessionKeyReceive,
			layer_2_dataObj.nonce,
			layer_2_dataObj.data
		);

		return {
			from: layer_3_dataObj.from,
			type: layer_2_dataObj.type,
			date: layer_2_dataObj.date,
			data: data,
		};
	}
}
