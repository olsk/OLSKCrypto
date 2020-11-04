const openpgp = require('openpgp');

const mod = {

	OLSKCryptoHMACSHA256Hash (param1, param2) {
		if (typeof param1 !== 'string') {
			throw new Error('OLSKErrorInputNotValid');
		}

		if (!param1.trim()) {
			throw new Error('OLSKErrorInputNotValid');
		}

		if (typeof param2 !== 'string') {
			throw new Error('OLSKErrorInputNotValid');
		}

		return (new (require('jshashes')).SHA256).hex_hmac(param1, param2);
	},

	OLSKCryptoShortHash (inputData) {
		if (typeof inputData !== 'string') {
			throw new Error('OLSKErrorInputNotValid');
		}

		if (!inputData.trim()) {
			throw new Error('OLSKErrorInputNotValid');
		}

		return mod.OLSKCryptoHMACSHA256Hash(inputData, inputData).slice(0, 32);
	},

	async OLSKCryptoEncryptSigned (param1, param2, param3) {
		if (typeof param1 !== 'string') {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (!param1.trim()) {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (typeof param2 !== 'string') {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (!param2.trim()) {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (typeof param3 !== 'string') {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (!param3.trim()) {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

    return (await openpgp.encrypt({
      message: openpgp.message.fromText(param3),
      publicKeys: [(await openpgp.key.readArmored(param1)).keys[0]],
      privateKeys: [(await openpgp.key.readArmored(param2)).keys[0]],
    })).data;
	},

	async OLSKCryptoDecryptSigned (param1, param2, param3) {
		if (typeof param1 !== 'string') {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (!param1.trim()) {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (typeof param2 !== 'string') {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (!param2.trim()) {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (typeof param3 !== 'string') {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		if (!param3.trim()) {
			return Promise.reject(new Error('OLSKErrorInputNotValid'));
		}

		const { data: decrypted, signatures: [{valid: isSigned}] } = await openpgp.decrypt({
		  message: await openpgp.message.readArmored(param3),
		  privateKeys: [(await openpgp.key.readArmored(param1)).keys[0]],
		  publicKeys: [(await openpgp.key.readArmored(param2)).keys[0]],
		});

		if (!isSigned) {
			return Promise.reject(new Error('OLSKErrorNotSigned'));
		}

		return decrypted;
	},

};

Object.assign(exports, mod);
