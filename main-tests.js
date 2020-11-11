const { throws, rejects, deepEqual } = require('assert');

const mod = require('./main.js');

const cryptico = require('cryptico');

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

	it('throws if param1 not string', function () {
		throws(function () {
			mod.OLSKCryptoShortHash(null);
		}, /OLSKErrorInputNotValid/);
	});
	
	it('throws if param1 not filled', function () {
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

		deepEqual(cryptico.decrypt(await mod.OLSKCryptoEncryptSigned(pairs.PAIR_RECEIVER_PUBLIC, pairs.PAIR_SENDER_PRIVATE, item), cryptico.RSAKey.parse(pairs.PAIR_RECEIVER_PRIVATE)), {
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

describe('OLSKCryptoEncryptGuardMiddleware', function test_OLSKCryptoEncryptGuardMiddleware() {

	const _OLSKCryptoEncryptGuardMiddleware = function (inputData) {
		return mod.OLSKCryptoEncryptGuardMiddleware({
			_FakeEnv: Object.assign({
				OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC: Math.random().toString(),
				OLSK_CRYPTO_PAIR_SENDER_PRIVATE: Math.random().toString(),
			}, inputData),
		}, {}, function (inputData) {
			return inputData;
		});
	};

	it('returns error if OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC not string', function() {
		deepEqual(_OLSKCryptoEncryptGuardMiddleware({
			OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC: null,
		}), new Error('OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC not defined'));
	});

	it('returns error if OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC not filled', function() {
		deepEqual(_OLSKCryptoEncryptGuardMiddleware({
			OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC: ' ',
		}), new Error('OLSK_CRYPTO_PAIR_RECEIVER_PUBLIC blank'));
	});

	it('returns error if OLSK_CRYPTO_PAIR_SENDER_PRIVATE not string', function() {
		deepEqual(_OLSKCryptoEncryptGuardMiddleware({
			OLSK_CRYPTO_PAIR_SENDER_PRIVATE: null,
		}), new Error('OLSK_CRYPTO_PAIR_SENDER_PRIVATE not defined'));
	});

	it('returns error if OLSK_CRYPTO_PAIR_SENDER_PRIVATE not filled', function() {
		deepEqual(_OLSKCryptoEncryptGuardMiddleware({
			OLSK_CRYPTO_PAIR_SENDER_PRIVATE: ' ',
		}), new Error('OLSK_CRYPTO_PAIR_SENDER_PRIVATE blank'));
	});

	it('returns undefined', function() {
		deepEqual(_OLSKCryptoEncryptGuardMiddleware(), undefined);
	});

});
