const _cryptico = require('cryptico');
const cryptico = _cryptico.default || _cryptico;

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

		return cryptico.encrypt(param3, param1, cryptico.RSAKey.parse(param2)).cipher;
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

		const data = cryptico.decrypt(param3, cryptico.RSAKey.parse(param1))

		if (data.signature !== 'verified' || data.publicKeyString !== param2) {
			return Promise.reject(new Error('OLSKErrorNotSigned'));
		}

		return data.plaintext;
	},

	OLSKCryptoEncryptGuardMiddleware (req, res, next) {
		return next((function (inputData) {
			if (typeof inputData !== 'object' || inputData === null) {
				throw new Error('RCSErrorInputNotValid');
			}

			if (!inputData.OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC) {
				return new Error('OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC not defined');
			}

			if (!inputData.OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC.trim()) {
				return new Error('OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC blank');
			}

			if (!inputData.OLSK_CRYPTO_PAIR_SENDER_PRIVATE) {
				return new Error('OLSK_CRYPTO_PAIR_SENDER_PRIVATE not defined');
			}

			if (!inputData.OLSK_CRYPTO_PAIR_SENDER_PRIVATE.trim()) {
				return new Error('OLSK_CRYPTO_PAIR_SENDER_PRIVATE blank');
			}
		})(req._FakeEnv || process.env));
	},

};

Object.assign(exports, mod);
