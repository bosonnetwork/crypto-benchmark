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

import org.apache.tuweni.crypto.sodium.Box;
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
import org.openjdk.jmh.infra.Blackhole;

/**
 * The X25519 key-agreement half of crypto_box (per-handshake cost).
 * <p>
 * Note: libsodium's {@code beforenm} performs the X25519 scalar-mult and then an HSalsa20
 * finalization to derive the shared key; the BC measurement is the X25519 scalar-mult
 * alone (BC exposes no public HSalsa20 core). The scalar-mult dominates, so the comparison
 * is representative, but native carries a small extra step not reflected on the BC side.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class KeyAgreementBenchmark {
	// libsodium
	private Box.PublicKey lsPublicKey;
	private Box.SecretKey lsSecretKey;

	// Bouncy Castle
	private byte[] bcSecretKey;
	private byte[] bcPublicKey;

	@Setup
	public void setup() {
		Box.KeyPair self = Box.KeyPair.random();
		Box.KeyPair peer = Box.KeyPair.random();
		lsPublicKey = peer.publicKey();
		lsSecretKey = self.secretKey();

		SecureRandom rnd = new SecureRandom();
		bcSecretKey = new byte[32];
		rnd.nextBytes(bcSecretKey);
		byte[] peerSk = new byte[32];
		rnd.nextBytes(peerSk);
		bcPublicKey = Bc.x25519PublicFromPrivate(peerSk);
	}

	@Benchmark
	public void libsodium_beforenm(Blackhole bh) {
		try (Box box = Box.forKeys(lsPublicKey, lsSecretKey)) {
			bh.consume(box);
		}
	}

	@Benchmark
	public byte[] bc_x25519_agreement() {
		return Bc.x25519Agreement(bcSecretKey, bcPublicKey);
	}
}
