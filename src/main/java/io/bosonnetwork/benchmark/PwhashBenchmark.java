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
import java.util.concurrent.TimeUnit;

import org.apache.tuweni.crypto.sodium.PasswordHash;
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
 * Argon2id password hashing (crypto_pwhash): libsodium vs Bouncy Castle, with identical
 * "interactive" parameters (opslimit=2, memlimit=64 MiB, parallelism=1). Local-only,
 * deliberately slow - measured to confirm FFI dispatch is negligible against the hash cost.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
public class PwhashBenchmark {
	// libsodium crypto_pwhash INTERACTIVE limits for Argon2id.
	private static final long OPS_LIMIT = 2L;
	private static final long MEM_LIMIT_BYTES = 67108864L; // 64 MiB
	private static final int MEM_KIB = (int) (MEM_LIMIT_BYTES / 1024);
	private static final int PARALLELISM = 1;
	private static final int OUT_LEN = 32;

	private byte[] password;
	private byte[] saltBytes;
	private PasswordHash.Salt lsSalt;

	@Setup
	public void setup() {
		password = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);
		saltBytes = new byte[PasswordHash.Salt.length()]; // 16
		new SecureRandom().nextBytes(saltBytes);
		lsSalt = PasswordHash.Salt.fromBytes(saltBytes);
	}

	@Benchmark
	public byte[] libsodium_argon2id() {
		return PasswordHash.hash(password, OUT_LEN, lsSalt, OPS_LIMIT, MEM_LIMIT_BYTES,
				PasswordHash.Algorithm.argon2id13());
	}

	@Benchmark
	public byte[] bc_argon2id() {
		return Bc.argon2id(password, saltBytes, (int) OPS_LIMIT, MEM_KIB, PARALLELISM, OUT_LEN);
	}
}
