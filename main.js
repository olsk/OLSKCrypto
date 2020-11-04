const mod = {

	OLSKCryptoHMACSHA256Hash (param1, param2) {
		if (typeof param1 !== 'string') {
			throw new Error('RCSErrorInputNotValid');
		}

		if (!param1.trim()) {
			throw new Error('RCSErrorInputNotValid');
		}

		if (typeof param2 !== 'string') {
			throw new Error('RCSErrorInputNotValid');
		}

		return (new (require('jshashes')).SHA256).hex_hmac(param1, param2);
	},

	OLSKCryptoShortHash (inputData) {
		if (typeof inputData !== 'string') {
			throw new Error('RCSErrorInputNotValid');
		}

		if (!inputData.trim()) {
			throw new Error('RCSErrorInputNotValid');
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

    return (await require('openpgp').encrypt({
      message: require('openpgp').message.fromText(param3),
      publicKeys: [(await require('openpgp').key.readArmored(param1)).keys[0]],
      privateKeys: [(await require('openpgp').key.readArmored(param2)).keys[0]],
    })).data;
	},

};

Object.assign(exports, mod);
