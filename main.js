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

};

Object.assign(exports, mod);
