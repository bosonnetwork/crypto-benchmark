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

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.apache.tuweni.crypto.sodium.KeyDerivation;
import org.apache.tuweni.crypto.sodium.PasswordHash;
import org.apache.tuweni.crypto.sodium.SecretBox;
import org.apache.tuweni.crypto.sodium.Signature;

/**
 * Byte-compatibility sanity check: proves the Bouncy Castle implementations in {@link Bc}
 * produce output identical to libsodium for the wire-critical constructions. This both
 * de-risks BC as a future backend and confirms the benchmarks measure equivalent work.
 *
 * Run:  java -cp target/benchmarks.jar io.bosonnetwork.benchmark.Interop
 * Exit code is non-zero if any vector mismatches.
 */
public final class Interop {
	private static int failures = 0;

	public static void main(String[] args) {
		SecureRandom rnd = new SecureRandom();

		checkEd25519(rnd);
		checkSecretBox(rnd);
		checkKdf(rnd);
		checkArgon2id(rnd);

		System.out.println();
		if (failures == 0) {
			System.out.println("ALL INTEROP CHECKS PASSED - BC output matches libsodium.");
			System.exit(0);
		} else {
			System.out.println(failures + " INTEROP CHECK(S) FAILED.");
			System.exit(1);
		}
	}

	private static void checkEd25519(SecureRandom rnd) {
		byte[] seed = new byte[32];
		rnd.nextBytes(seed);
		byte[] message = "boson ed25519 interop".getBytes(StandardCharsets.UTF_8);

		Signature.KeyPair kp = Signature.KeyPair.fromSeed(Signature.Seed.fromBytes(seed));
		byte[] lsSig = Signature.signDetached(message, kp.secretKey());
		byte[] bcSig = Bc.ed25519Sign(seed, message);
		report("Ed25519 detached signature (BC == libsodium)", Arrays.equals(lsSig, bcSig));

		byte[] bcPub = Bc.ed25519PublicFromSeed(seed);
		report("Ed25519 public key from seed (BC == libsodium)",
				Arrays.equals(bcPub, kp.publicKey().bytesArray()));
		report("Ed25519 cross-verify: BC verifies libsodium signature",
				Bc.ed25519Verify(bcPub, message, lsSig));
		report("Ed25519 cross-verify: libsodium verifies BC signature",
				Signature.verifyDetached(message, bcSig, kp.publicKey()));
	}

	private static void checkSecretBox(SecureRandom rnd) {
		byte[] key = new byte[SecretBox.Key.length()];
		byte[] nonce = new byte[SecretBox.Nonce.length()];
		rnd.nextBytes(key);
		rnd.nextBytes(nonce);
		byte[] message = "boson secretbox interop payload".getBytes(StandardCharsets.UTF_8);

		byte[] lsCipher = SecretBox.encrypt(message, SecretBox.Key.fromBytes(key),
				SecretBox.Nonce.fromBytes(nonce));
		byte[] bcCipher = Bc.secretboxEncrypt(message, key, nonce);
		report("crypto_secretbox ciphertext (BC == libsodium)", Arrays.equals(lsCipher, bcCipher));

		byte[] bcOfLs = Bc.secretboxDecrypt(lsCipher, key, nonce);
		report("secretbox cross-decrypt: BC decrypts libsodium ciphertext",
				Arrays.equals(bcOfLs, message));
		byte[] lsOfBc = SecretBox.decrypt(bcCipher, SecretBox.Key.fromBytes(key),
				SecretBox.Nonce.fromBytes(nonce));
		report("secretbox cross-decrypt: libsodium decrypts BC ciphertext",
				Arrays.equals(lsOfBc, message));
	}

	private static void checkKdf(SecureRandom rnd) {
		byte[] master = new byte[KeyDerivation.MasterKey.length()];
		rnd.nextBytes(master);
		byte[] context = "boson-kd".getBytes(StandardCharsets.US_ASCII); // 8 bytes
		long subKeyId = 42L;

		byte[] lsKey = KeyDerivation.MasterKey.fromBytes(master).deriveKeyArray(32, subKeyId, context);
		byte[] bcKey = Bc.kdfDerive(master, subKeyId, context, 32);
		report("crypto_kdf derived sub-key (BC == libsodium)", Arrays.equals(lsKey, bcKey));
	}

	private static void checkArgon2id(SecureRandom rnd) {
		byte[] password = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);
		byte[] salt = new byte[PasswordHash.Salt.length()];
		rnd.nextBytes(salt);

		long ops = 2L;
		long memBytes = 67108864L;
		byte[] lsKey = PasswordHash.hash(password, 32, PasswordHash.Salt.fromBytes(salt), ops, memBytes,
				PasswordHash.Algorithm.argon2id13());
		byte[] bcKey = Bc.argon2id(password, salt, (int) ops, (int) (memBytes / 1024), 1, 32);
		report("Argon2id derived key (BC == libsodium)", Arrays.equals(lsKey, bcKey));
	}

	private static void report(String name, boolean ok) {
		System.out.printf("[%s] %s%n", ok ? "PASS" : "FAIL", name);
		if (!ok)
			failures++;
	}
}
