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

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import org.apache.tuweni.crypto.sodium.SecretBox;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * crypto_secretbox (XSalsa20-Poly1305) - the per-message half of crypto_box once the
 * shared key is precomputed (beforenm). This is the bulk-symmetric path that dominates
 * relay throughput (active-proxy). Swept across payload sizes to locate the BC-vs-native
 * crossover; native should pull ahead as size grows (SIMD).
 *
 * Throughput is reported in ops/s; multiply by the payload size for MB/s.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class SecretBoxBenchmark {
	@Param({"64", "1024", "16384", "262144"})
	public int size;

	private byte[] message;

	// libsodium
	private SecretBox.Key lsKey;
	private SecretBox.Nonce lsNonce;
	private byte[] lsCipher;

	// Bouncy Castle (same key/nonce -> identical ciphertext, see Interop)
	private byte[] bcKey;
	private byte[] bcNonce;
	private byte[] bcCipher;

	@Setup
	public void setup() {
		SecureRandom rnd = new SecureRandom();
		message = new byte[size];
		rnd.nextBytes(message);

		bcKey = new byte[SecretBox.Key.length()];   // 32
		bcNonce = new byte[SecretBox.Nonce.length()]; // 24
		rnd.nextBytes(bcKey);
		rnd.nextBytes(bcNonce);

		lsKey = SecretBox.Key.fromBytes(bcKey);
		lsNonce = SecretBox.Nonce.fromBytes(bcNonce);

		lsCipher = SecretBox.encrypt(message, lsKey, lsNonce);
		bcCipher = Bc.secretboxEncrypt(message, bcKey, bcNonce);
	}

	@Benchmark
	public byte[] libsodium_encrypt() {
		return SecretBox.encrypt(message, lsKey, lsNonce);
	}

	@Benchmark
	public byte[] libsodium_decrypt() {
		return SecretBox.decrypt(lsCipher, lsKey, lsNonce);
	}

	@Benchmark
	public byte[] bc_encrypt() {
		return Bc.secretboxEncrypt(message, bcKey, bcNonce);
	}

	@Benchmark
	public byte[] bc_decrypt() {
		return Bc.secretboxDecrypt(bcCipher, bcKey, bcNonce);
	}
}
