(function() {

const { throws, rejects, deepEqual } = require('assert');

const mod = require('./main.js');

const cryptico = require('cryptico');
const aesjs = require('aes-js');

const uPairs = async function () {
	const sender = cryptico.generateRSAKey(Math.random().toString(), 1024);
	const receiver = cryptico.generateRSAKey(Math.random().toString(), 1024);

	return {
		PAIR_RECEIVER_PRIVATE: JSON.stringify(receiver.toJSON()),
		PAIR_SENDER_PUBLIC: cryptico.publicKeyString(sender),

		PAIR_RECEIVER_PUBLIC: cryptico.publicKeyString(receiver),
		PAIR_SENDER_PRIVATE: JSON.stringify(sender.toJSON()),
	};
};

describe('OLSKCryptoHMACSHA256Hash', function test_OLSKCryptoHMACSHA256Hash() {

	it('throws if param1 not string', function () {
		throws(function () {
			mod.OLSKCryptoHMACSHA256Hash(null, 'bravo');
		}, /OLSKErrorInputNotValid/);
	});
	
	it('throws if param1 not filled', function () {
		throws(function () {
			mod.OLSKCryptoHMACSHA256Hash(' ', 'bravo');
		}, /OLSKErrorInputNotValid/);
	});
	
	it('throws if param2 not string', function () {
		throws(function () {
			mod.OLSKCryptoHMACSHA256Hash('alfa', null);
		}, /OLSKErrorInputNotValid/);
	});
	
	it('returns string', function () {
		deepEqual(mod.OLSKCryptoHMACSHA256Hash('alfa', 'bravo'), '25d2e75b48936ef7aa543040b8c704c12860cc74606cfc2151e170a4d5215fe7');
	});
	
	it('matches canonical results', function () {
		deepEqual(mod.OLSKCryptoHMACSHA256Hash('key', 'The quick brown fox jumps over the lazy dog'), 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8');
		deepEqual(mod.OLSKCryptoHMACSHA256Hash('abcdefg', 'I love cupcakes'), 'c0fa1bc00531bd78ef38c628449c5102aeabd49b5dc3a2a516ea6ea959d6658e');
	});

});

describe('OLSKCryptoShortHash', function test_OLSKCryptoShortHash() {

	it('throws if not string', function () {
		throws(function () {
			mod.OLSKCryptoShortHash(null);
		}, /OLSKErrorInputNotValid/);
	});
	
	it('throws if not filled', function () {
		throws(function () {
			mod.OLSKCryptoShortHash(' ');
		}, /OLSKErrorInputNotValid/);
	});
	
	it('returns string', function () {
		deepEqual(mod.OLSKCryptoShortHash('alfa'), mod.OLSKCryptoHMACSHA256Hash('alfa', 'alfa').slice(0, 32));
	});

});

describe('OLSKCryptoEncryptSigned', function test_OLSKCryptoEncryptSigned() {

	it('rejects if param1 not string', async function () {
		await rejects(mod.OLSKCryptoEncryptSigned(null, 'bravo', 'charlie'), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param1 not filled', async function () {
		await rejects(mod.OLSKCryptoEncryptSigned(' ', 'bravo', 'charlie'), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param2 not string', async function () {
		await rejects(mod.OLSKCryptoEncryptSigned('alfa', null, 'charlie'), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param2 not filled', async function () {
		await rejects(mod.OLSKCryptoEncryptSigned('alfa', ' ', 'charlie'), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param3 not string', async function () {
		await rejects(mod.OLSKCryptoEncryptSigned('alfa', 'bravo', null), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param3 not filled', async function () {
		await rejects(mod.OLSKCryptoEncryptSigned('alfa', 'bravo', ' '), /OLSKErrorInputNotValid/);
	});
	
	it('returns string', async function () {
		const item = Math.random().toString();
		const pairs = await uPairs();

		deepEqual(cryptico.decrypt(await mod.OLSKCryptoEncryptSigned(pairs.PAIR_RECEIVER_PUBLIC, pairs.PAIR_SENDER_PRIVATE, item), (cryptico.RSAKey || RSAKey).parse(pairs.PAIR_RECEIVER_PRIVATE)), {
			plaintext: item,
			status: 'success',
			signature: 'verified',
			publicKeyString: pairs.PAIR_SENDER_PUBLIC,
		});
	});
	
});

describe('OLSKCryptoDecryptSigned', function test_OLSKCryptoDecryptSigned() {

	it('rejects if param1 not string', async function () {
		await rejects(mod.OLSKCryptoDecryptSigned(null, 'bravo', 'charlie'), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param1 not filled', async function () {
		await rejects(mod.OLSKCryptoDecryptSigned(' ', 'bravo', 'charlie'), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param2 not string', async function () {
		await rejects(mod.OLSKCryptoDecryptSigned('alfa', null, 'charlie'), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param2 not filled', async function () {
		await rejects(mod.OLSKCryptoDecryptSigned('alfa', ' ', 'charlie'), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param3 not string', async function () {
		await rejects(mod.OLSKCryptoDecryptSigned('alfa', 'bravo', null), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if param3 not filled', async function () {
		await rejects(mod.OLSKCryptoDecryptSigned('alfa', 'bravo', ' '), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if not signed', async function () {
		const pairs = await uPairs();
		await rejects(mod.OLSKCryptoDecryptSigned(pairs.PAIR_RECEIVER_PRIVATE, pairs.PAIR_RECEIVER_PUBLIC, await mod.OLSKCryptoEncryptSigned(pairs.PAIR_RECEIVER_PUBLIC, pairs.PAIR_SENDER_PRIVATE, Math.random().toString())), /OLSKErrorNotSigned/);
	});
	
	it('returns string', async function () {
		const item = Math.random().toString();
		const pairs = await uPairs();

		deepEqual(await mod.OLSKCryptoDecryptSigned(pairs.PAIR_RECEIVER_PRIVATE, pairs.PAIR_SENDER_PUBLIC, await mod.OLSKCryptoEncryptSigned(pairs.PAIR_RECEIVER_PUBLIC, pairs.PAIR_SENDER_PRIVATE, item)), item);
	});
	
});

describe('OLSKCryptoPBKDF2Key', function test_OLSKCryptoPBKDF2Key() {

	it('rejects if not string', async function () {
		await rejects(mod.OLSKCryptoPBKDF2Key(null), /OLSKErrorInputNotValid/);
	});
	
	it('rejects if not filled', async function () {
		await rejects(mod.OLSKCryptoPBKDF2Key(' '), /OLSKErrorInputNotValid/);
	});
	
	it('matches canonical results', async function () {
		deepEqual(aesjs.utils.hex.fromBytes(await mod.OLSKCryptoPBKDF2Key('The quick brown fox jumps over the lazy dog')), 'e2c2d7208d78918f620c0aba9fdd83c8');
		deepEqual(aesjs.utils.hex.fromBytes(await mod.OLSKCryptoPBKDF2Key('I love cupcakes')), '4d783f1f6bda8f80d0ed4f5d156dc919');
	});

});

describe('OLSKCryptoPBKDF2Hash', function test_OLSKCryptoPBKDF2Hash() {

	it('returns string', async function () {
		const item = await mod.OLSKCryptoPBKDF2Key(Math.random().toString());
		deepEqual(mod.OLSKCryptoPBKDF2Hash(item), aesjs.utils.hex.fromBytes(item));
	});
	
	it('matches canonical results', async function () {
		deepEqual(mod.OLSKCryptoPBKDF2Hash(await mod.OLSKCryptoPBKDF2Key('The quick brown fox jumps over the lazy dog')), 'e2c2d7208d78918f620c0aba9fdd83c8');
		deepEqual(mod.OLSKCryptoPBKDF2Hash(await mod.OLSKCryptoPBKDF2Key('I love cupcakes')), '4d783f1f6bda8f80d0ed4f5d156dc919');
	});

});

describe('OLSKCryptoAESEncrypt', function test_OLSKCryptoAESEncrypt() {

	it('throws if param2 not string', function () {
		throws(function () {
			mod.OLSKCryptoAESEncrypt(Math.random(), null);
		}, /OLSKErrorInputNotValid/);
	});
	
	it('returns string', async function () {
		const key = await mod.OLSKCryptoPBKDF2Key(Math.random().toString());
		const message = Math.random().toString();
		deepEqual(mod.OLSKCryptoAESEncrypt(key, message), aesjs.utils.hex.fromBytes((new aesjs.ModeOfOperation.ctr(key)).encrypt(aesjs.utils.utf8.toBytes(message))));
	});
	
	it('matches canonical results', async function () {
		const item = 'alfa';
		deepEqual(mod.OLSKCryptoAESEncrypt(await mod.OLSKCryptoPBKDF2Key('The quick brown fox jumps over the lazy dog'), item), '22c054bc');
		deepEqual(mod.OLSKCryptoAESEncrypt(await mod.OLSKCryptoPBKDF2Key('I love cupcakes'), item), '389380be');
	});
	
});

describe('OLSKCryptoAESDecrypt', function test_OLSKCryptoAESDecrypt() {

	it('throws if param2 not string', function () {
		throws(function () {
			mod.OLSKCryptoAESDecrypt(Math.random(), null);
		}, /OLSKErrorInputNotValid/);
	});
	
	it('returns string', async function () {
		const key = await mod.OLSKCryptoPBKDF2Key(Math.random().toString());
		const message = Math.random().toString();
		deepEqual(mod.OLSKCryptoAESDecrypt(key, mod.OLSKCryptoAESEncrypt(key, message)), message);
	});
	
});

describe('OLSKCryptoAESFunctions', function test_OLSKCryptoAESFunctions() {

	const uNative = function (inputData) {
		const token = '[native code]';
		return inputData.split(token).map(function (e) {
			return e.trim();
		}).join(token)
	};

	it('throws if not string', function () {
		throws(function () {
			mod.OLSKCryptoAESFunctions(null);
		}, /OLSKErrorInputNotValid/);
	});
	
	it('throws if not filled', function () {
		throws(function () {
			mod.OLSKCryptoAESFunctions(' ');
		}, /OLSKErrorInputNotValid/);
	});
	
	it('returns object', function () {
		deepEqual(typeof mod.OLSKCryptoAESFunctions(Math.random().toString()), 'object');
	});

	context('OLSKCryptoAESFunctionsEncrypt', function () {

		it('throws if not string', function () {
			throws(function () {
				mod.OLSKCryptoAESFunctions(Math.random().toString()).OLSKCryptoAESFunctionsEncrypt(null);
			}, /OLSKErrorInputNotValid/);
		});
		
		it('returns string', async function () {
			const object = mod.OLSKCryptoAESFunctions(mod.OLSKCryptoPBKDF2Hash(await mod.OLSKCryptoPBKDF2Key(Math.random().toString())));
			const message = Math.random().toString();
			deepEqual(object.OLSKCryptoAESFunctionsEncrypt(message), mod.OLSKCryptoAESEncrypt(object._OLSKCryptoAESFunctionsKey, message));
		});

		it('stringifies to native code', function () {
			deepEqual(uNative(mod.OLSKCryptoAESFunctions(Math.random().toString()).OLSKCryptoAESFunctionsEncrypt.toString()), 'function () {[native code]}');
		});
	
	});

	context('OLSKCryptoAESFunctionsDecrypt', function () {

		it('throws if not string', function () {
			throws(function () {
				mod.OLSKCryptoAESFunctions(Math.random().toString()).OLSKCryptoAESFunctionsDecrypt(null);
			}, /OLSKErrorInputNotValid/);
		});
		
		it('returns string', async function () {
			const object = mod.OLSKCryptoAESFunctions(mod.OLSKCryptoPBKDF2Hash(await mod.OLSKCryptoPBKDF2Key(Math.random().toString())));
			const message = Math.random().toString();
			deepEqual(object.OLSKCryptoAESFunctionsDecrypt(object.OLSKCryptoAESFunctionsEncrypt(message)), message);
		});

		it('stringifies to native code', function () {
			deepEqual(uNative(mod.OLSKCryptoAESFunctions(Math.random().toString()).OLSKCryptoAESFunctionsDecrypt.toString()), 'function () {[native code]}');
		});
	
	});

});
	
})();
