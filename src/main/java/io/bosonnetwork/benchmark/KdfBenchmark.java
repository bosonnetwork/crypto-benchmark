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

import org.apache.tuweni.crypto.sodium.KeyDerivation;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * crypto_kdf sub-key derivation (keyed Blake2b): libsodium vs Bouncy Castle.
 * Rare in Boson (sub-key derivation), included for completeness / sanity.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class KdfBenchmark {
	private static final int SUBKEY_LEN = 32;
	private static final long SUBKEY_ID = 1L;

	private byte[] masterKey;
	private byte[] context; // 8 bytes
	private KeyDerivation.MasterKey lsMaster;

	@Setup
	public void setup() {
		SecureRandom rnd = new SecureRandom();
		masterKey = new byte[KeyDerivation.MasterKey.length()]; // 32
		rnd.nextBytes(masterKey);
		context = "boson-kd".getBytes(java.nio.charset.StandardCharsets.US_ASCII); // 8 bytes
		lsMaster = KeyDerivation.MasterKey.fromBytes(masterKey);
	}

	@Benchmark
	public byte[] libsodium_kdf() {
		return lsMaster.deriveKeyArray(SUBKEY_LEN, SUBKEY_ID, context);
	}

	@Benchmark
	public byte[] bc_kdf() {
		return Bc.kdfDerive(masterKey, SUBKEY_ID, context, SUBKEY_LEN);
	}
}
