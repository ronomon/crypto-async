# crypto-async
Native Cipher, Hash, and HMAC operations executed in Node's threadpool for multi-core throughput.

## Motivation
#### Some issues with parts of the `crypto` module
* `crypto` cipher, hash and hmac streams are not really asynchronous. They execute in C++, but only in the main thread and so they still block the event loop. Encrypting 64 MB of data might block the event loop for +/- 70ms. Hashing 64 MB of data might block the event loop for +/- 190ms.
* These `crypto` operations do not take advantage of multiple CPU cores. Your server may have 4 cores available but `crypto` will use only 1 of these 4 cores for all encrypting and hashing operations.
* These `crypto` operations were not designed to use statically allocated buffers. They allocate a new output buffer when encrypting or hashing data, even if you already have an output buffer available. If you want to hash only a portion of a buffer you must first create a slice. Thousands of JS object allocations put unnecessary strain on the GC. This in turn leads to longer GC pauses which also block the event loop.
* These `crypto` operations require multiple roundtrips between JS and C++ even if you are only encrypting or hashing a single buffer.
* These `crypto` operations are not suitable for high-throughput network protocols or filesystems which need to checksum and encrypt/decrypt large amounts of data. Such a user-space network protocol or filesystem using `crypto` might actually saturate a single CPU core with crypto operations before saturating a fast local network or SSD disk.

#### Some new ideas with the `crypto-async` module
* Truly asynchronous. All calls execute asynchronously in the `node.js` threadpool. This keeps the main thread and event loop free without blocking.
* Scalable across multiple CPU cores. While `crypto-async` is a fraction slower per call than `crypto` (possibly because of the overhead of interacting with the threadpool), for buffers larger than 1024 bytes it shines and provides N-cores more throughput. `crypto-async` achieves up to 3x more throughput compared to `crypto`.
* Zero-copy. All keys, ivs, source and target arguments can be passed directly using offsets into existing buffers, without requiring any slices and without allocating any temporary output buffers. This enables predictable memory usage for programs with tight memory budgets.
* Designed to support the common use-case of encrypting or hashing a single buffer, where memory is adequate and buffers are already in memory. This avoids multiple round-trips between JS and C++.
* Separates the control plane from the data plane to enable high-throughput applications.

## Performance
```

           CPU: Intel(R) Xeon(R) CPU E3-1230 V2 @ 3.30GHz
         Cores: 8
   Concurrency: 4

============================================================

   AES-256-CTR: 10000 x 256 Bytes
        crypto: Latency: 0.009ms Throughput: 24.62 MB/s
  crypto-async: Latency: 0.039ms Throughput: 25.86 MB/s

   AES-256-CTR: 10000 x 1024 Bytes
        crypto: Latency: 0.011ms Throughput: 91.43 MB/s
  crypto-async: Latency: 0.039ms Throughput: 103.43 MB/s

   AES-256-CTR: 10000 x 4096 Bytes
        crypto: Latency: 0.019ms Throughput: 186.18 MB/s
  crypto-async: Latency: 0.038ms Throughput: 417.96 MB/s

   AES-256-CTR: 1024 x 65536 Bytes
        crypto: Latency: 0.091ms Throughput: 699.05 MB/s
  crypto-async: Latency: 0.095ms Throughput: 2684.35 MB/s

   AES-256-CTR: 64 x 1048576 Bytes
        crypto: Latency: 1.105ms Throughput: 945.20 MB/s
  crypto-async: Latency: 1.362ms Throughput: 3050.40 MB/s

============================================================

   HASH-SHA256: 10000 x 256 Bytes
        crypto: Latency: 0.005ms Throughput: 43.39 MB/s
  crypto-async: Latency: 0.038ms Throughput: 25.10 MB/s

   HASH-SHA256: 10000 x 1024 Bytes
        crypto: Latency: 0.010ms Throughput: 96.60 MB/s
  crypto-async: Latency: 0.029ms Throughput: 140.27 MB/s

   HASH-SHA256: 10000 x 4096 Bytes
        crypto: Latency: 0.016ms Throughput: 246.75 MB/s
  crypto-async: Latency: 0.038ms Throughput: 422.27 MB/s

   HASH-SHA256: 1024 x 65536 Bytes
        crypto: Latency: 0.192ms Throughput: 338.93 MB/s
  crypto-async: Latency: 0.242ms Throughput: 1065.22 MB/s

   HASH-SHA256: 64 x 1048576 Bytes
        crypto: Latency: 3.023ms Throughput: 347.71 MB/s
  crypto-async: Latency: 3.162ms Throughput: 1290.56 MB/s

============================================================

   HMAC-SHA256: 10000 x 256 Bytes
        crypto: Latency: 0.008ms Throughput: 27.23 MB/s
  crypto-async: Latency: 0.039ms Throughput: 25.35 MB/s

   HMAC-SHA256: 10000 x 1024 Bytes
        crypto: Latency: 0.011ms Throughput: 80.63 MB/s
  crypto-async: Latency: 0.032ms Throughput: 123.37 MB/s

   HMAC-SHA256: 10000 x 4096 Bytes
        crypto: Latency: 0.020ms Throughput: 197.87 MB/s
  crypto-async: Latency: 0.039ms Throughput: 390.10 MB/s

   HMAC-SHA256: 1024 x 65536 Bytes
        crypto: Latency: 0.195ms Throughput: 335.54 MB/s
  crypto-async: Latency: 0.279ms Throughput: 945.20 MB/s

   HMAC-SHA256: 64 x 1048576 Bytes
        crypto: Latency: 3.134ms Throughput: 335.54 MB/s
  crypto-async: Latency: 3.974ms Throughput: 1048.58 MB/s

```

## Installation
This will install `crypto-async` and compile the native binding automatically:
```
npm install crypto-async
```

## Usage

#### Cipher
```
var cryptoAsync = require('crypto-async');
var algorithm = 'AES-256-CTR';
var encrypt = 1; // 0 = Decrypt, 1 = Encrypt
var key = new Buffer(1024);
var keyOffset = 4;
var keySize = 32;
var iv = new Buffer(32);
var ivOffset = 2;
var ivSize = 16;
var source = new Buffer(1024 * 1024);
var sourceOffset = 512;
var sourceSize = 65536;
var target = new Buffer(1024 * 1024);
var targetOffset = 32768;
cryptoAsync.cipher(
  algorithm,
  encrypt,
  key,
  keyOffset,
  keySize,
  iv,
  ivOffset,
  ivSize,
  source,
  sourceOffset,
  sourceSize,
  target,
  targetOffset,
  function(error, targetSize) {}
);
```

#### Hash
```
var cryptoAsync = require('crypto-async');
var algorithm = 'SHA256';
var source = new Buffer(1024 * 1024);
var sourceOffset = 512;
var sourceSize = 65536;
var target = new Buffer(1024 * 1024);
var targetOffset = 32768;
cryptoAsync.hash(
  algorithm,
  source,
  sourceOffset,
  sourceSize,
  target,
  targetOffset,
  function(error) {}
);
```

#### HMAC
```
var cryptoAsync = require('crypto-async');
var algorithm = 'SHA256';
var key = new Buffer(1024);
var keyOffset = 4;
var keySize = 8;
var source = new Buffer(1024 * 1024);
var sourceOffset = 512;
var sourceSize = 65536;
var target = new Buffer(1024 * 1024);
var targetOffset = 32768;
cryptoAsync.hmac(
  algorithm,
  key,
  keyOffset,
  keySize,
  source,
  sourceOffset,
  sourceSize,
  target,
  targetOffset,
  function(error) {}
);
```

## Tests
`crypto-async` ships with a long-running fuzz test:

```
node test.js
```

## Benchmark
To benchmark `crypto-async` vs `crypto`:
```
node benchmark.js
```

### AEAD Ciphers

AEAD ciphers such as GCM are not currently supported and may be added in future as an `aead` method.
