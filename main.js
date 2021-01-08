if (typeof require === 'undefined') {
	require = function (inputData) {
		return {
			'assert': {
				throws: chai.assert.throws,
				rejects: (function (chain, err) {
					return chain.catch(function(m) { chai.assert.match(m, err); });
				}),
				deepEqual: chai.assert.deepEqual,
			},
			'crypto': {
				pbkdf2: (function (chain, err) {}),
			},
			'./main.js': window.OLSKCrypto,
			'cryptico': window.cryptico,
			'jshashes': window.Hashes,
			'aes-js': window.aesjs,
		}[inputData];
	};
};

(function(global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
		typeof define === 'function' && define.amd ? define(['exports'], factory) :
			(factory((global.OLSKCrypto = global.OLSKCrypto || {})));
}(this, (function(exports) { 'use strict';

const _cryptico = require('cryptico');
const cryptico = _cryptico.default || _cryptico;
const aesjs = require('aes-js');

const kBitCount = 128;
const kSHACount = 512;

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

		return cryptico.encrypt(param3, param1, (cryptico.RSAKey ||	 RSAKey).parse(param2)).cipher;
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

		const data = cryptico.decrypt(param3, (cryptico.RSAKey ||	 RSAKey).parse(param1))

		if (data.signature !== 'verified' || data.publicKeyString !== param2) {
			return Promise.reject(new Error('OLSKErrorNotSigned'));
		}

		return data.plaintext;
	},

	async OLSKCryptoPBKDF2Key (inputData) {
		if (typeof inputData !== 'string') {
			throw new Error('OLSKErrorInputNotValid');
		}

		if (!inputData.trim()) {
			throw new Error('OLSKErrorInputNotValid');
		}

		if (typeof window === 'undefined' || window.OLSKRequire) {
			const _require = typeof window !== 'undefined' ? OLSKRequire : require;
			return new Promise(function (res, rej) {
				return _require('crypto').pbkdf2(inputData, inputData, 1, kBitCount / 8, 'sha' + kSHACount, function (err, result) {
					return err ? rej(err) : res(result);
				});
			});
		}

		return window.crypto.subtle.importKey('raw', aesjs.utils.utf8.toBytes(inputData), 'PBKDF2', false, ['deriveBits','deriveKey']).then(function (keyMaterial) {
			return window.crypto.subtle.deriveBits({
				name: 'PBKDF2',
				salt: aesjs.utils.utf8.toBytes(inputData),
				iterations: 1,
				hash: { name: 'SHA-' + kSHACount },
			}, keyMaterial, kBitCount).then(function (result) {
				return new Uint8Array(result);
			});
		});
	},

	OLSKCryptoPBKDF2Hash (inputData) {
		return aesjs.utils.hex.fromBytes(inputData);
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

		const _OLSKCryptoAESFunctionsKey = aesjs.utils.hex.toBytes(inputData);

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

	Object.defineProperty(exports, '__esModule', {
		value: true
	});

})));
