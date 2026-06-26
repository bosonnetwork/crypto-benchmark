/*
 * Copyright (c) 2023 -      bosonnetwork.io
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package io.bosonnetwork.benchmark;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;

/**
 * Pure-Java Bouncy Castle implementations of the primitives Boson uses, written to be
 * byte-for-byte compatible with the corresponding libsodium constructions so the
 * benchmark and {@link Interop} compare equivalent work.
 *
 * <ul>
 *   <li>Ed25519 detached signatures (RFC 8032)</li>
 *   <li>crypto_secretbox: XSalsa20-Poly1305 (the per-message half of crypto_box)</li>
 *   <li>X25519 scalar multiplication (the key-agreement half of crypto_box)</li>
 *   <li>crypto_kdf: keyed Blake2b with libsodium's salt/personal framing</li>
 *   <li>Argon2id (crypto_pwhash)</li>
 * </ul>
 */
final class Bc {
	private Bc() {
	}

	// ---- Ed25519 -----------------------------------------------------------

	static byte[] ed25519PublicFromSeed(byte[] seed) {
		return new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
	}

	static byte[] ed25519Sign(byte[] seed, byte[] message) {
		Ed25519PrivateKeyParameters sk = new Ed25519PrivateKeyParameters(seed, 0);
		Ed25519Signer signer = new Ed25519Signer();
		signer.init(true, sk);
		signer.update(message, 0, message.length);
		return signer.generateSignature();
	}

	static boolean ed25519Verify(byte[] publicKey, byte[] message, byte[] signature) {
		Ed25519PublicKeyParameters pk = new Ed25519PublicKeyParameters(publicKey, 0);
		Ed25519Signer verifier = new Ed25519Signer();
		verifier.init(false, pk);
		verifier.update(message, 0, message.length);
		return verifier.verifySignature(signature);
	}

	// ---- X25519 (crypto_box key agreement) ---------------------------------

	static byte[] x25519PublicFromPrivate(byte[] sk) {
		byte[] pk = new byte[X25519.POINT_SIZE];
		X25519.scalarMultBase(sk, 0, pk, 0);
		return pk;
	}

	static byte[] x25519Agreement(byte[] sk, byte[] pk) {
		byte[] shared = new byte[X25519.POINT_SIZE];
		X25519.calculateAgreement(sk, 0, pk, 0, shared, 0);
		return shared;
	}

	// ---- crypto_secretbox: XSalsa20-Poly1305 -------------------------------
	// NaCl/libsodium crypto_secretbox_easy: the first 32 bytes of the XSalsa20
	// keystream are the Poly1305 one-time key; the message is then encrypted with
	// the keystream continuing from offset 32. Output layout is tag(16) || cipher.

	static final int MAC_BYTES = 16;

	static byte[] secretboxEncrypt(byte[] message, byte[] key32, byte[] nonce24) {
		XSalsa20Engine cipher = new XSalsa20Engine();
		cipher.init(true, new ParametersWithIV(new KeyParameter(key32), nonce24));

		byte[] subkey = new byte[32];
		cipher.processBytes(new byte[32], 0, 32, subkey, 0); // consume first 32 keystream bytes

		byte[] out = new byte[MAC_BYTES + message.length];
		cipher.processBytes(message, 0, message.length, out, MAC_BYTES);

		Poly1305 mac = new Poly1305();
		mac.init(new KeyParameter(subkey));
		mac.update(out, MAC_BYTES, message.length);
		mac.doFinal(out, 0); // tag at [0, 16)
		return out;
	}

	static byte[] secretboxDecrypt(byte[] boxed, byte[] key32, byte[] nonce24) {
		int clen = boxed.length - MAC_BYTES;

		XSalsa20Engine cipher = new XSalsa20Engine();
		cipher.init(true, new ParametersWithIV(new KeyParameter(key32), nonce24));

		byte[] subkey = new byte[32];
		cipher.processBytes(new byte[32], 0, 32, subkey, 0);

		Poly1305 mac = new Poly1305();
		mac.init(new KeyParameter(subkey));
		mac.update(boxed, MAC_BYTES, clen);
		byte[] tag = new byte[MAC_BYTES];
		mac.doFinal(tag, 0);

		if (!Arrays.constantTimeAreEqual(MAC_BYTES, tag, 0, boxed, 0))
			throw new IllegalStateException("secretbox authentication failed");

		byte[] message = new byte[clen];
		cipher.processBytes(boxed, MAC_BYTES, clen, message, 0);
		return message;
	}

	// ---- crypto_kdf: keyed Blake2b -----------------------------------------
	// libsodium crypto_kdf_blake2b_derive_from_key:
	//   salt[16]     = LE64(subkey_id) || 0...0
	//   personal[16] = ctx[0..8]       || 0...0
	//   blake2b(out, outlen, in=empty, key=master, salt, personal)

	static byte[] kdfDerive(byte[] masterKey32, long subKeyId, byte[] context8, int outLen) {
		byte[] salt = new byte[16];
		for (int i = 0; i < 8; i++)
			salt[i] = (byte) (subKeyId >>> (8 * i));
		byte[] personal = new byte[16];
		System.arraycopy(context8, 0, personal, 0, 8);

		Blake2bDigest digest = new Blake2bDigest(masterKey32, outLen, salt, personal);
		byte[] out = new byte[outLen];
		digest.doFinal(out, 0); // no input bytes
		return out;
	}

	// ---- Argon2id (crypto_pwhash) ------------------------------------------

	static byte[] argon2id(byte[] password, byte[] salt, int iterations, int memoryKiB,
			int parallelism, int outLen) {
		Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
				.withVersion(Argon2Parameters.ARGON2_VERSION_13)
				.withIterations(iterations)
				.withMemoryAsKB(memoryKiB)
				.withParallelism(parallelism)
				.withSalt(salt)
				.build();
		Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(params);
		byte[] out = new byte[outLen];
		generator.generateBytes(password, out);
		return out;
	}
}
