const _sodium = require('libsodium-wrappers');

export class Prism {
	private _Ipk: any;
	private _Isk: any;

	public sodium: any;

	constructor(Ipk: any = null, Isk: any = null) {
		this._Ipk = Ipk;
		this._Isk = Isk;
	}

	async init() {
		await _sodium.ready;
		this.sodium = _sodium;
	}

	public get Ipk() {
		return this._Ipk;
	}

	public get Isk() {
		return this._Isk;
	}

	public toBase64(data: any): any{
		return this.sodium.to_base64(
			data,
			this.sodium.base64_variants.URLSAFE_NO_PADDING
		);
	}

	public fromBase64(data: any): any{
		return this.sodium.from_base64(
			data,
			this.sodium.base64_variants.URLSAFE_NO_PADDING
		);
	}

	public generateIdentityKeys(): any {
		let {publicKey: Ipk, privateKey: Isk} = this.sodium.crypto_box_keypair();
		this._Ipk = this.toBase64(Ipk);
		this._Isk = this.toBase64(Isk);
		return {
			Ipk: this.Ipk,
			Isk: this.Isk
		};
	}

	public unauthenticatedAsymetricEncrypt(packet: any, recipientIpk: any): any {
		let cipher = this.sodium.crypto_box_seal(
			JSON.stringify(packet),
			this.fromBase64(recipientIpk)
		);
		return this.toBase64(cipher);
	}

	public unauthenticatedAsymetricDecrypt(cipher: any): any {
		let payload = this.sodium.crypto_box_seal_open(
			this.fromBase64(cipher),
			this.fromBase64(this.Ipk),
			this.fromBase64(this.Isk)
		);
		return JSON.parse(this.sodium.to_string(payload));
	}

	public authenticatedAsymetricEncrypt(packet: any, recipientIpk: any): any {
		let nonce = this.sodium.randombytes_buf(this.sodium.crypto_box_NONCEBYTES);

		let cipher = this.sodium.crypto_box_easy(
			JSON.stringify(packet),
			nonce,
			this.fromBase64(recipientIpk),
			this.fromBase64(this.Isk)
		);

		return {
			nonce: this.toBase64(nonce),
			cipher: this.toBase64(cipher)
		};
	}

	public authenticatedAsymetricDecrypt(cipher: any, nonce: any, senderIpk: any): any {
		const data = JSON.parse(
			this.sodium.to_string(
				this.sodium.crypto_box_open_easy(
					this.fromBase64(cipher),
					this.fromBase64(nonce),
					this.fromBase64(senderIpk),
					this.fromBase64(this.Isk)
				)
			)
		);
		return data;
	}

	public symmetricEncrypt(payload: any, key: any = null): any {
		if (key == null) {
			key = this.sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
		} else {
			key = this.fromBase64(key);
		}

		let nonce: any = this.sodium.randombytes_buf(
			this.sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
		);

		let cipher: any =
			this.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
				JSON.stringify(payload),
				null,
				null,
				nonce,
				key
			);

		return {
			key: this.toBase64(key),
			nonce: this.toBase64(nonce),
			cipher: this.toBase64(cipher)
		};
	}

	public symmetricDecrypt(cipher: any, key: any, nonce: any): any {
		let payload: any = this.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
			null,
			this.fromBase64(cipher),
			null,
			this.fromBase64(nonce),
			this.fromBase64(key)
		);
		return JSON.parse(this.sodium.to_string(payload));
	}

	public generateSessionKeys(): any {
		let {publicKey: pk, privateKey: sk}: any = this.sodium.crypto_kx_keypair();
		return {
			pk: this.toBase64(pk),
			sk: this.toBase64(sk),
		};
	}

	public generateSharedSessionKeysRequest(
		pk: any,
		sk: any,
		sender_pk: any
	): any {
		let { sharedRx: rx, sharedTx: tx }: any = this.sodium.crypto_kx_client_session_keys(
			this.fromBase64(pk),
			this.fromBase64(sk),
			this.fromBase64(sender_pk)
		);

		return {
			rx: this.toBase64(rx),
			tx: this.toBase64(tx),
		};
	}

	public generateSharedSessionKeysResponse(
		pk: any,
		sk: any,
		sender_pk: any
	): any {
		let { sharedRx: rx, sharedTx: tx }: any = this.sodium.crypto_kx_server_session_keys(
			this.fromBase64(pk),
			this.fromBase64(sk),
			this.fromBase64(sender_pk)
		);

		return {
			rx: this.toBase64(rx),
			tx: this.toBase64(tx)
		};
	}

	public sessionKeyDerivation(
		key: any,
		cnt: number,
		context: String = '___PRISM'
	): any {
		let derivedKey = this.sodium.crypto_kdf_derive_from_key(
			this.sodium.crypto_kdf_KEYBYTES,
			cnt,
			context,
			this.fromBase64(key)
		);

		return this.toBase64(derivedKey);
	}

	public layer0_encrypt(payload: any, tx: any): any {
		const symmetricEncrypt = this.symmetricEncrypt(payload, tx);
		return {
			nonce: symmetricEncrypt.nonce,
			cipher: symmetricEncrypt.cipher,
		};
	}

	public layer0_decrypt(cipher: any, rx: any, nonce: any): any {
		return this.symmetricDecrypt(cipher, rx, nonce);
	}

	public layer1_encrypt(layer0_cipher: any, layer0_nonce: any, recipiantIpk: any, type: any, cnt: any): any {
		let {nonce, cipher} = this.authenticatedAsymetricEncrypt(
			JSON.stringify({
				type: type,
				date: Date.now(),
				cnt: cnt,
				nonce: layer0_nonce,
				data: layer0_cipher,
			}),
			recipiantIpk
		);

		return {
			nonce: nonce,
			cipher: cipher,
		};
	}

	public layer1_decrypt(layer2_cipher: any, layer2_nonce: any, senderIpk: any): any {
		const packet = JSON.parse(this.authenticatedAsymetricDecrypt(layer2_cipher, layer2_nonce, senderIpk));
		return {
			type: packet.type,
			date: packet.date,
			cnt: packet.cnt,
			nonce: packet.nonce,
			data: packet.data,
		};
	}

	public layer2_encrypt(layer1_cipher: any, layer1_nonce: any, recipiantIpk: any): any {
		let cipher = this.unauthenticatedAsymetricEncrypt(
			JSON.stringify({
				from: this.Ipk,
				nonce: layer1_nonce,
				data: layer1_cipher,
			}),
			recipiantIpk
		);
		return cipher;
	}

	public layer2_decrypt(cipher: any): any {
		let payload = JSON.parse(this.unauthenticatedAsymetricDecrypt(cipher));
		return payload;
	}

	public layer_encrypt(packet: any, tx: any, recipiantIpk: any, type: any, cnt: any): any {
		let layer0_encrypt: any = this.layer0_encrypt(packet, tx);
		let layer1_encrypt: any = this.layer1_encrypt(layer0_encrypt.cipher, layer0_encrypt.nonce, recipiantIpk, type, cnt);
		let layer2_encrypt: any = this.layer2_encrypt(layer1_encrypt.cipher, layer1_encrypt.nonce, recipiantIpk);
		return layer2_encrypt;
	}

	public layer_decrypt(cipher: any): any {
		let layer2_decrypt: any = this.layer2_decrypt(cipher);
		let layer1_decrypt: any = this.layer1_decrypt(layer2_decrypt.data, layer2_decrypt.nonce, layer2_decrypt.from);
		
		// Because the sender is only known after layer2 decryption, you must perform the layer0 decryption manually.
		return layer1_decrypt;
	}
}
