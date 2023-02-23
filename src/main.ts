const _sodium = require('libsodium-wrappers');

export class Prism {
	private _IdentityKeys: any;
	public sodium: any;

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
		this._IdentityKeys.public = this.sodium.to_base64(
			publicKey,
			this.sodium.base64_variants.ORIGINAL
		);
		this._IdentityKeys.private = this.sodium.to_base64(
			privateKey,
			this.sodium.base64_variants.ORIGINAL
		);
		return this.IdentityKeys;
	}

	public publicEncrypt(message: any, recipientPublicKey: any): any {
		let cypherText = this.sodium.crypto_box_seal(
			JSON.stringify(message),
			this.sodium.from_base64(
				recipientPublicKey,
				this.sodium.base64_variants.ORIGINAL
			)
		);
		return this.sodium.to_base64(
			cypherText,
			this.sodium.base64_variants.ORIGINAL
		);
	}

	public publicDecrypt(cypherText: any): any {
		let plainText = this.sodium.crypto_box_seal_open(
			this.sodium.from_base64(cypherText, this.sodium.base64_variants.ORIGINAL),
			this.sodium.from_base64(
				this.IdentityKeys.public,
				this.sodium.base64_variants.ORIGINAL
			),
			this.sodium.from_base64(
				this.IdentityKeys.private,
				this.sodium.base64_variants.ORIGINAL
			)
		);
		return JSON.parse(this.sodium.to_string(plainText));
	}

	public boxEncrypt(data: any, recipientPublicKey: any): any {
		let nonce = this.sodium.randombytes_buf(this.sodium.crypto_box_NONCEBYTES);

		let cypherText = this.sodium.crypto_box_easy(
			JSON.stringify(data),
			nonce,
			this.sodium.from_base64(
				recipientPublicKey,
				this.sodium.base64_variants.ORIGINAL
			),
			this.sodium.from_base64(
				this.IdentityKeys.private,
				this.sodium.base64_variants.ORIGINAL
			)
		);

		return {
			nonce: this.sodium.to_base64(nonce, this.sodium.base64_variants.ORIGINAL),
			cypherText: this.sodium.to_base64(
				cypherText,
				this.sodium.base64_variants.ORIGINAL
			),
		};
	}

	public boxDecrypt(cypherText: any, nonce: any, from: any): any {
		const data = JSON.parse(
			this.sodium.to_string(
				this.sodium.crypto_box_open_easy(
					this.sodium.from_base64(
						cypherText,
						this.sodium.base64_variants.ORIGINAL
					),
					this.sodium.from_base64(nonce, this.sodium.base64_variants.ORIGINAL),
					this.sodium.from_base64(from, this.sodium.base64_variants.ORIGINAL),
					this.sodium.from_base64(
						this.IdentityKeys.private,
						this.sodium.base64_variants.ORIGINAL
					)
				)
			)
		);
		return data;
	}

	public symmetricEncrypt(data: any, key: any = null): any {
		if (key == null) {
			key = this.sodium.crypto_aead_chacha20poly1305_keygen();
		} else {
			key = this.sodium.from_base64(key, this.sodium.base64_variants.ORIGINAL);
		}

		let nonce: any = this.sodium.randombytes_buf(
			this.sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
		);

		let cypherText: any =
			this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
				JSON.stringify(data),
				null,
				null,
				nonce,
				key
			);

		return {
			key: this.sodium.to_base64(key, this.sodium.base64_variants.ORIGINAL),
			nonce: this.sodium.to_base64(nonce, this.sodium.base64_variants.ORIGINAL),
			cypherText: this.sodium.to_base64(
				cypherText,
				this.sodium.base64_variants.ORIGINAL
			),
		};
	}

	public symmetricDecrypt(key: any, nonce: any, cypherText: any): any {
		let message: any = this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
			null,
			this.sodium.from_base64(cypherText, this.sodium.base64_variants.ORIGINAL),
			null,
			this.sodium.from_base64(nonce, this.sodium.base64_variants.ORIGINAL),
			this.sodium.from_base64(key, this.sodium.base64_variants.ORIGINAL)
		);
		return JSON.parse(this.sodium.to_string(message));
	}

	public generateSessionKeys(): any {
		let { publicKey, privateKey }: any = this.sodium.crypto_kx_keypair();
		return {
			publicKey: this.sodium.to_base64(
				publicKey,
				this.sodium.base64_variants.ORIGINAL
			),
			privateKey: this.sodium.to_base64(
				privateKey,
				this.sodium.base64_variants.ORIGINAL
			),
		};
	}

	public generateSharedSessionKeysInitial(
		sessionPublicKey: any,
		sessionPrivateKey: any,
		partnerPublicKey: any
	): any {
		let { sharedRx, sharedTx }: any = this.sodium.crypto_kx_client_session_keys(
			this.sodium.from_base64(
				sessionPublicKey,
				this.sodium.base64_variants.ORIGINAL
			),
			this.sodium.from_base64(
				sessionPrivateKey,
				this.sodium.base64_variants.ORIGINAL
			),
			this.sodium.from_base64(
				partnerPublicKey,
				this.sodium.base64_variants.ORIGINAL
			)
		);

		return {
			receiveKey: this.sodium.to_base64(
				sharedRx,
				this.sodium.base64_variants.ORIGINAL
			),
			sendKey: this.sodium.to_base64(
				sharedTx,
				this.sodium.base64_variants.ORIGINAL
			),
		};
	}

	public generateSharedSessionKeysResponse(
		sessionPublicKey: any,
		sessionPrivateKey: any,
		partnerPublicKey: any
	): any {
		let { sharedRx, sharedTx }: any = this.sodium.crypto_kx_server_session_keys(
			this.sodium.from_base64(
				sessionPublicKey,
				this.sodium.base64_variants.ORIGINAL
			),
			this.sodium.from_base64(
				sessionPrivateKey,
				this.sodium.base64_variants.ORIGINAL
			),
			this.sodium.from_base64(
				partnerPublicKey,
				this.sodium.base64_variants.ORIGINAL
			)
		);

		return {
			receiveKey: this.sodium.to_base64(
				sharedRx,
				this.sodium.base64_variants.ORIGINAL
			),
			sendKey: this.sodium.to_base64(
				sharedTx,
				this.sodium.base64_variants.ORIGINAL
			),
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
			this.sodium.from_base64(key, this.sodium.base64_variants.ORIGINAL)
		);

		return this.sodium.to_base64(
			derivedKey,
			this.sodium.base64_variants.ORIGINAL
		);
	}

	public prismEncrypt_Layer1(data: any, sharedSessionKeySend: any): any {
		// Layer 1
		// Encrypt data object symmetrically if type is MESSAGE.
		const symmetricEncrypt = this.symmetricEncrypt(data, sharedSessionKeySend);
		return {
			nonce: symmetricEncrypt.nonce,
			cypherText: symmetricEncrypt.cypherText,
		};
	}

	public prismEncrypt_Layer2(
		type: string,
		count: number,
		layer_1_nonce: any,
		layer_1_cypherText: any,
		recipientPublicIdentityKey: any
	): any {
		// Layer 2
		// Encrypt data generated in layer 1 with crypto_secret_box to verify identity and encrypt sensitive data.
		let layer_2_nonce = this.sodium.randombytes_buf(
			this.sodium.crypto_box_NONCEBYTES
		);

		let layer_2_cypherText = this.sodium.crypto_box_easy(
			JSON.stringify({
				type: type,
				date: Date.now(),
				count: count,
				nonce: layer_1_nonce,
				data: layer_1_cypherText,
			}),
			layer_2_nonce,
			this.sodium.from_base64(
				recipientPublicIdentityKey,
				this.sodium.base64_variants.ORIGINAL
			),
			this.sodium.from_base64(
				this.IdentityKeys.private,
				this.sodium.base64_variants.ORIGINAL
			)
		);

		return {
			nonce: this.sodium.to_base64(
				layer_2_nonce,
				this.sodium.base64_variants.ORIGINAL
			),
			cypherText: this.sodium.to_base64(
				layer_2_cypherText,
				this.sodium.base64_variants.ORIGINAL
			),
		};
	}
	public prismEncrypt_Layer3(layer_2_nonce: any, layer_2_cypherText: any): any {
		// Layer 3
		// Encrypt data generated in layer 2 with a random symmetric key.
		return this.symmetricEncrypt({
			from: this.IdentityKeys.public,
			nonce: layer_2_nonce,
			data: layer_2_cypherText,
		});
	}
	public prismEncrypt_Layer4(
		layer_3_key: any,
		layer_3_nonce: any,
		layer_3_cypherText: any,
		recipientPublicIdentityKey: any
	): any {
		// Layer 4
		// Encrypt layer 3 obj with recipients public key.
		let layer_4_cypherText: any = this.publicEncrypt(
			{
				key: layer_3_key,
				nonce: layer_3_nonce,
			},
			recipientPublicIdentityKey
		);

		return `${layer_4_cypherText}:${layer_3_cypherText}`;
	}

	public prismDecrypt_Layer1(
		nonce: any,
		cypherText: any,
		sharedSessionKeyReceive: any
	): any {
		return this.symmetricDecrypt(sharedSessionKeyReceive, nonce, cypherText);
	}

	public prismDecrypt_Layer2(nonce: any, cypherText: any, from: any): any {
		const symmetricDecrypted = JSON.parse(
			this.sodium.to_string(
				this.sodium.crypto_box_open_easy(
					this.sodium.from_base64(
						cypherText,
						this.sodium.base64_variants.ORIGINAL
					),
					this.sodium.from_base64(nonce, this.sodium.base64_variants.ORIGINAL),
					this.sodium.from_base64(from, this.sodium.base64_variants.ORIGINAL),
					this.sodium.from_base64(
						this.IdentityKeys.private,
						this.sodium.base64_variants.ORIGINAL
					)
				)
			)
		);
		return {
			type: symmetricDecrypted.type,
			count: symmetricDecrypted.count,
			date: symmetricDecrypted.date,
			nonce: symmetricDecrypted.nonce,
			cypherText: symmetricDecrypted.data,
		};
	}
	public prismDecrypt_Layer3(nonce: any, key: any, cypherText: any): any {
		let symmetricDecrypt = this.symmetricDecrypt(key, nonce, cypherText);
		return {
			from: symmetricDecrypt.from,
			nonce: symmetricDecrypt.nonce,
			cypherText: symmetricDecrypt.data,
		};
	}
	public prismDecrypt_Layer4(dataObj: any): any {
		let [layer_4_cypherText, layer_3_cypherText] = dataObj.split(':');
		let layer_4_dataObj = this.publicDecrypt(layer_4_cypherText);
		return {
			nonce: layer_4_dataObj.nonce,
			key: layer_4_dataObj.key,
			cypherText: layer_3_cypherText,
		};
	}
}
