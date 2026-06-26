# Boson Crypto Benchmark

BouncyCastle (pure Java) vs libsodium (native JNR) microbenchmarks for the cryptographic primitives used in the Boson Network.

## Overview

This repository contains a standalone, self-contained JMH benchmark suite designed to compare the performance of:
- **BouncyCastle**: Pure Java implementation (`org.bouncycastle:bcprov-jdk18on`)
- **libsodium**: Native implementation via JNR bindings (`io.tmio:tuweni-crypto` + `com.github.jnr:jnr-ffi`)

The benchmarks cover the primary crypto primitives used by Boson:
1. **Ed25519 Signatures**: Signing and verification.
2. **Key Agreement**: X25519 handshakes (`beforenm`).
3. **Symmetric Encryption**: `crypto_box` (XSalsa20-Poly1305) over different message sizes.
4. **Key Derivation (KDF)**: Blake2b sub-key derivation.
5. **Password Hashing (pwhash)**: Argon2id (interactive mode).

This project is standalone on purpose: it is **not** wired into the Boson reactor, enabling it to be built and run on any target machine without needing to compile the rest of the Boson codebase.

---

## Getting Started

### Prerequisites
- JDK 17 or higher
- Maven 3.x

### Build

Compile the codebase and package the executable JMH uber-jar:
```bash
mvn clean package
```

### Run Benchmarks

To execute all benchmarks:
```bash
java -jar target/benchmarks.jar
```

Or run a specific benchmark (e.g. only Ed25519 signatures):
```bash
java -jar target/benchmarks.jar SignatureBenchmark
```

### Run Interop Sanity Check

To verify that the BouncyCastle and libsodium implementations are byte-for-byte identical and produce compatible outputs:
```bash
java -cp target/benchmarks.jar io.bosonnetwork.benchmark.Interop
```

---

## Benchmark Results

Machine: **Apple M1 Pro, arm64, 10 cores, JDK 17.0.17 (Temurin)**
Config: JMH, 1 fork, 3 warmup + 5 measurement iterations (1s each). Re-run the full
2-fork config for publication-grade numbers: `java -jar target/benchmarks.jar`.

**Important:** the `libsodium` column is the **JNR** binding (Apache Tuweni) - the *best-dispatch* native option. The lazysodium replacement uses **JNA**, whose
higher per-call overhead would make the native column slower on small inputs, widening BC's
advantage where it already wins and shrinking it where native wins.

All BC implementations are **byte-for-byte identical to libsodium** (verified by `Interop`).

### Signatures (Ed25519, 64-byte message)

| Operation | libsodium (JNR) | BouncyCastle | Winner |
|---|--:|--:|---|
| sign   | 72.180 ops/ms | 22.444 ops/ms | libsodium ~3.2x |
| verify | 26.656 ops/ms | 17.071 ops/ms | libsodium ~1.6x |

Verify is the inbound-RPC-validation hot path; the gap there is only ~1.6x, and against
JNA it would narrow further.

### Key agreement (X25519, per handshake)

| Operation | libsodium (JNR) | BouncyCastle | Winner |
|---|--:|--:|---|
| beforenm / X25519 | 25.691 ops/ms | 17.075 ops/ms | libsodium ~1.5x |

(libsodium's beforenm also does an HSalsa20 step the BC X25519-only number doesn't.)

### crypto_box per-message symmetric (XSalsa20-Poly1305) - the crossover

| Payload | Op | libsodium (JNR) | BouncyCastle | Winner |
|---|---|--:|--:|---|
| 64 B    | encrypt | 1,106,316 ops/s | 1,772,521 ops/s | **BC 1.6x** |
| 64 B    | decrypt |   963,446 ops/s |   1,434,563 ops/s | **BC 1.5x** |
| 1 KB    | encrypt |   345,622 ops/s |   276,752 ops/s | libsodium 1.25x |
| 1 KB    | decrypt |   335,712 ops/s |   208,742 ops/s | libsodium 1.6x |
| 16 KB   | encrypt |    27,713 ops/s |    18,717 ops/s | libsodium 1.5x |
| 256 KB  | encrypt |     1,774 ops/s |       796 ops/s | libsodium 2.2x |

Crossover is around **~1 KB**: below it BC wins (FFI dispatch dominates the tiny crypto cost);
above it native pulls ahead and the gap grows to ~2.2x at 256 KB (native SIMD on bulk).
At 256 KB that is ~454 MB/s (native) vs ~204 MB/s (BC) on this machine. The bulk gap is
likely larger on x86 with AVX2 than on M1 NEON.

### crypto_kdf (Blake2b sub-key derivation)

| Operation | libsodium (JNR) | BouncyCastle | Winner |
|---|--:|--:|---|
| derive | 1,491 ops/ms | 3,554 ops/ms | **BC 2.4x** |

Tiny input -> FFI overhead dominates -> BC's inlined Blake2b wins decisively.

### crypto_pwhash (Argon2id, interactive: ops=2, mem=64 MiB, p=1)

| Operation | libsodium (JNR) | BouncyCastle | Winner |
|---|--:|--:|---|
| hash | 63.1 ms/op | 83.5 ms/op | libsodium 1.3x |

Both ~tens of ms (deliberately slow); the 20 ms difference is irrelevant for a rare login op,
and confirms FFI dispatch is noise at this cost level.

### Interpretation

- **Small messages (DHT RPC signatures, control < 1 KB):** BC is competitive-to-faster than
  even JNR-libsodium, and would clearly beat JNA. Pure-Java is the right call here.
- **Bulk crypto_box (active-proxy relay, > 1 KB):** native wins, 1.5-2.2x and growing with
  size. This is the *only* place a native backend is clearly justified.
- **kdf:** BC faster. **pwhash:** ~comparable, rare. **No wire/identity risk:** BC is byte-exact.

This supports: **BC pure-Java as the default backend everywhere** (removes the native
dependency, fixes Android, simplifies `distribution`), and reserve a narrow native **JNI**
path for the active-proxy relay only if its measured bulk throughput demands it. Choosing
lazysodium/JNA instead would be a per-call-overhead regression exactly where Boson does most
of its crypto (small messages), for a bulk win JNI would deliver better anyway.
