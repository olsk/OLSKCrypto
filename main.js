const _cryptico = require('cryptico');
const cryptico = _cryptico.default || _cryptico;
const bcrypt = require('bcryptjs');
const aesjs = require('aes-js');

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

	OLSKCryptoBcryptHash (inputData) {
		if (typeof inputData !== 'string') {
			throw new Error('OLSKErrorInputNotValid');
		}

		if (!inputData.trim()) {
			throw new Error('OLSKErrorInputNotValid');
		}

		return bcrypt.hashSync(inputData);
	},

	OLSKCryptoBcryptKey (inputData) {
		if (typeof inputData !== 'string') {
			throw new Error('OLSKErrorInputNotValid');
		}

		return aesjs.utils.utf8.toBytes(inputData.replace(bcrypt.getSalt(inputData), ' '));
	},

	OLSKCryptoAESEncrypt (key, param2) {
		if (typeof param2 !== 'string') {
			throw new Error('OLSKErrorInputNotValid');
		}

		return aesjs.utils.hex.fromBytes((new aesjs.ModeOfOperation.ctr(key)).encrypt(aesjs.utils.utf8.toBytes(param2)));
	},

	OLSKCryptoAESDecrypt (key, param2) {
		if (typeof param2 !== 'string') {
			throw new Error('OLSKErrorInputNotValid');
		}

		return aesjs.utils.utf8.fromBytes((new aesjs.ModeOfOperation.ctr(key)).decrypt(aesjs.utils.hex.toBytes(param2)));
	},

	OLSKCryptoAESFunctions (inputData) {
		if (typeof inputData !== 'string') {
			throw new Error('OLSKErrorInputNotValid');
		}

		if (!inputData.trim()) {
			throw new Error('OLSKErrorInputNotValid');
		}

		const _OLSKCryptoAESFunctionsKey = mod.OLSKCryptoBcryptKey(inputData);

		return {
			_OLSKCryptoAESFunctionsKey,

			OLSKCryptoAESFunctionsEncrypt: (function (inputData) {
				if (typeof inputData !== 'string') {
					throw new Error('OLSKErrorInputNotValid');
				}

				return mod.OLSKCryptoAESEncrypt(_OLSKCryptoAESFunctionsKey, inputData);
			}).bind(null),

			OLSKCryptoAESFunctionsDecrypt: (function (inputData) {
				if (typeof inputData !== 'string') {
					throw new Error('OLSKErrorInputNotValid');
				}

				return mod.OLSKCryptoAESDecrypt(_OLSKCryptoAESFunctionsKey, inputData);
			}).bind(null),
		};
	},	

};

Object.assign(exports, mod);
