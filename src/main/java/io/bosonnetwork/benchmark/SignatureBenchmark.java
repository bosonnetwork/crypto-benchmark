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

import org.apache.tuweni.crypto.sodium.Signature;
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
 * Ed25519 detached sign / verify: libsodium (Tuweni/JNR) vs Bouncy Castle (pure Java).
 * Fixed 64-byte message - the small-input regime where FFI dispatch overhead is a large
 * fraction of the work.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class SignatureBenchmark {
	private byte[] message;

	// libsodium
	private Signature.SecretKey lsSecretKey;
	private Signature.PublicKey lsPublicKey;
	private byte[] lsSignature;

	// Bouncy Castle (same Ed25519 seed -> identical keys, see Interop)
	private byte[] bcSeed;
	private byte[] bcPublicKey;
	private byte[] bcSignature;

	@Setup
	public void setup() {
		SecureRandom rnd = new SecureRandom();
		message = new byte[64];
		rnd.nextBytes(message);

		bcSeed = new byte[32];
		rnd.nextBytes(bcSeed);

		Signature.KeyPair kp = Signature.KeyPair.fromSeed(Signature.Seed.fromBytes(bcSeed));
		lsSecretKey = kp.secretKey();
		lsPublicKey = kp.publicKey();
		lsSignature = Signature.signDetached(message, lsSecretKey);

		bcPublicKey = Bc.ed25519PublicFromSeed(bcSeed);
		bcSignature = Bc.ed25519Sign(bcSeed, message);
	}

	@Benchmark
	public byte[] libsodium_sign() {
		return Signature.signDetached(message, lsSecretKey);
	}

	@Benchmark
	public boolean libsodium_verify() {
		return Signature.verifyDetached(message, lsSignature, lsPublicKey);
	}

	@Benchmark
	public byte[] bc_sign() {
		return Bc.ed25519Sign(bcSeed, message);
	}

	@Benchmark
	public boolean bc_verify() {
		return Bc.ed25519Verify(bcPublicKey, message, bcSignature);
	}
}
