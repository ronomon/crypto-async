# @ronomon/crypto-async
Fast, reliable cipher, hash and hmac methods executed in Node's threadpool for
multi-core throughput.

## Motivation
#### Some longstanding issues with Node's `crypto` module
* Did you know that Node's cipher, hash and hmac streams are not truly
asynchronous? They execute in C, but only in the main thread and so the `crypto`
module **blocks your event loop**. Encrypting 64 MB of data might block your
event loop for +/- 70ms. Hashing 64 MB of data might block your event loop for
+/- 190ms. This will spike any concurrent user-visible request latencies.
* Worse, the `crypto` module **does not take advantage of multiple CPU cores**.
Your server may have four CPU cores but `crypto` will use only one of these four
CPU cores for all encrypting and hashing operations. The `cluster` module with
its IPC overhead is not an efficient solution to multi-core crypto.
* The `crypto` module was sadly **not designed to use statically allocated
buffers**, allocating a new output buffer when encrypting or hashing data,
even if you already have an output buffer available. If you want to hash only a
portion of a buffer you must first create a slice. Creating thousands of
Javascript objects in this way **strains the GC**, leads to longer GC pauses and
further blocks your event loop.
* The `crypto` module forces **multiple unnecessary roundtrips between JS and
C** even if you are only encrypting or hashing a single buffer. When your buffer
is small (less than a few hundred bytes), this calling overhead alone, of a few
hundred nanoseconds per call, can double your latencies and halve your
throughput.
* In summary, the `crypto` module is **not suitable for high-throughput network
protocols or storage systems**, which need to checksum and encrypt/decrypt huge
amounts of data concurrently. Such a user-space network protocol or storage
system using the `crypto` module might saturate a single CPU core with crypto
operations well before saturating a fast local network or SSD disk.

#### Some new ideas for `@ronomon/crypto-async`
* **Truly asynchronous.** All operations can execute asynchronously in Node's
threadpool. This keeps your event loop free from blocking.
* **Scales across multiple CPU cores.** While `@ronomon/crypto-async` is a
fraction slower per call than `crypto` because of the overhead of pushing tasks
into the threadpool, for buffers larger than 1024 bytes it shines and provides
nearly N-cores more throughput. Don't let your CPU cores go to waste.
* **Zero-copy.** All keys, ivs, source and target arguments can be passed
directly using offsets into existing buffers, without requiring any slices and
without allocating any temporary output buffers. This enables predictable memory
usage for programs with tight memory budgets.
* **Fast.** Supports the common use case of encrypting or hashing a single
buffer, to avoid multiple round-trips between JS and C. This halves latencies
and doubles throughput for small buffers.
* **Synchronous where it makes sense.** While you should use asynchronous
methods for large buffers to improve throughput, you can also use synchronous
methods for small buffers to achieve optimal latency.

## Performance
```

                CPU: Intel(R) Xeon(R) CPU E3-1230 V2 @ 3.30GHz
              Cores: 8
            Threads: 4

========================================================================

        aes-256-ctr: 16384 x 256 Bytes
               node: Latency: 0.008ms Throughput: 29.09 MB/s
      sync @ronomon: Latency: 0.003ms Throughput: 76.70 MB/s
     async @ronomon: Latency: 0.047ms Throughput: 21.04 MB/s

        aes-256-ctr: 16384 x 1024 Bytes
               node: Latency: 0.007ms Throughput: 132.43 MB/s
      sync @ronomon: Latency: 0.003ms Throughput: 340.46 MB/s
     async @ronomon: Latency: 0.045ms Throughput: 88.86 MB/s

        aes-256-ctr: 16384 x 4096 Bytes
               node: Latency: 0.009ms Throughput: 439.00 MB/s
      sync @ronomon: Latency: 0.004ms Throughput: 1010.11 MB/s
     async @ronomon: Latency: 0.043ms Throughput: 376.36 MB/s

        aes-256-ctr: 1024 x 65536 Bytes
               node: Latency: 0.046ms Throughput: 1402.22 MB/s
      sync @ronomon: Latency: 0.030ms Throughput: 2154.93 MB/s
     async @ronomon: Latency: 0.088ms Throughput: 2938.77 MB/s

        aes-256-ctr: 64 x 1048576 Bytes
               node: Latency: 0.717ms Throughput: 1460.21 MB/s
      sync @ronomon: Latency: 0.452ms Throughput: 2314.90 MB/s
     async @ronomon: Latency: 1.372ms Throughput: 3013.60 MB/s

========================================================================

        aes-256-gcm: 16384 x 256 Bytes
               node: Latency: 0.009ms Throughput: 27.99 MB/s
      sync @ronomon: Latency: 0.003ms Throughput: 82.62 MB/s
     async @ronomon: Latency: 0.042ms Throughput: 24.11 MB/s

        aes-256-gcm: 16384 x 1024 Bytes
               node: Latency: 0.009ms Throughput: 105.41 MB/s
      sync @ronomon: Latency: 0.004ms Throughput: 253.50 MB/s
     async @ronomon: Latency: 0.042ms Throughput: 94.61 MB/s

        aes-256-gcm: 16384 x 4096 Bytes
               node: Latency: 0.013ms Throughput: 314.20 MB/s
      sync @ronomon: Latency: 0.006ms Throughput: 621.70 MB/s
     async @ronomon: Latency: 0.043ms Throughput: 375.18 MB/s

        aes-256-gcm: 1024 x 65536 Bytes
               node: Latency: 0.091ms Throughput: 719.20 MB/s
      sync @ronomon: Latency: 0.061ms Throughput: 1065.52 MB/s
     async @ronomon: Latency: 0.113ms Throughput: 2285.47 MB/s

        aes-256-gcm: 64 x 1048576 Bytes
               node: Latency: 1.063ms Throughput: 986.12 MB/s
      sync @ronomon: Latency: 0.944ms Throughput: 1109.59 MB/s
     async @ronomon: Latency: 1.516ms Throughput: 2715.93 MB/s

========================================================================

             sha256: 16384 x 256 Bytes
               node: Latency: 0.007ms Throughput: 36.79 MB/s
      sync @ronomon: Latency: 0.002ms Throughput: 101.47 MB/s
     async @ronomon: Latency: 0.042ms Throughput: 24.05 MB/s

             sha256: 16384 x 1024 Bytes
               node: Latency: 0.008ms Throughput: 124.19 MB/s
      sync @ronomon: Latency: 0.004ms Throughput: 224.30 MB/s
     async @ronomon: Latency: 0.043ms Throughput: 92.59 MB/s

             sha256: 16384 x 4096 Bytes
               node: Latency: 0.016ms Throughput: 240.94 MB/s
      sync @ronomon: Latency: 0.013ms Throughput: 319.26 MB/s
     async @ronomon: Latency: 0.040ms Throughput: 398.04 MB/s

             sha256: 2048 x 65536 Bytes
               node: Latency: 0.201ms Throughput: 325.30 MB/s
      sync @ronomon: Latency: 0.188ms Throughput: 349.06 MB/s
     async @ronomon: Latency: 0.273ms Throughput: 955.41 MB/s

             sha256: 128 x 1048576 Bytes
               node: Latency: 3.013ms Throughput: 347.94 MB/s
      sync @ronomon: Latency: 3.003ms Throughput: 349.09 MB/s
     async @ronomon: Latency: 3.310ms Throughput: 1257.44 MB/s

========================================================================

        hmac-sha256: 16384 x 256 Bytes
               node: Latency: 0.009ms Throughput: 27.94 MB/s
      sync @ronomon: Latency: 0.003ms Throughput: 69.70 MB/s
     async @ronomon: Latency: 0.038ms Throughput: 26.30 MB/s

        hmac-sha256: 16384 x 1024 Bytes
               node: Latency: 0.010ms Throughput: 97.52 MB/s
      sync @ronomon: Latency: 0.006ms Throughput: 176.88 MB/s
     async @ronomon: Latency: 0.036ms Throughput: 111.07 MB/s

        hmac-sha256: 16384 x 4096 Bytes
               node: Latency: 0.019ms Throughput: 212.33 MB/s
      sync @ronomon: Latency: 0.014ms Throughput: 285.50 MB/s
     async @ronomon: Latency: 0.039ms Throughput: 411.16 MB/s

        hmac-sha256: 2048 x 65536 Bytes
               node: Latency: 0.198ms Throughput: 330.22 MB/s
      sync @ronomon: Latency: 0.191ms Throughput: 342.88 MB/s
     async @ronomon: Latency: 0.256ms Throughput: 1019.00 MB/s

        hmac-sha256: 128 x 1048576 Bytes
               node: Latency: 3.025ms Throughput: 346.55 MB/s
      sync @ronomon: Latency: 2.926ms Throughput: 358.31 MB/s
     async @ronomon: Latency: 3.214ms Throughput: 1298.56 MB/s

```

## Installation
This will install `@ronomon/crypto-async` and compile the native binding
automatically:
```
npm install @ronomon/crypto-async
```

## Usage

#### Adjust threadpool size and control concurrency
Node runs filesystem and DNS operations in the threadpool. The threadpool
consists of 4 threads by default, which is far from optimal. This means that at
most 4 operations can be running at any point in time. If any operation is slow
to complete, it will cause head-of-line blocking, otherwise known as the Convoy
effect.

The size of the threadpool should therefore be increased at startup time (at the
top of your script, before requiring any modules) by setting the
`UV_THREADPOOL_SIZE` environment variable. The absolute maximum is 128 threads,
which requires only ~1 MB memory in total according to the
[libuv docs](http://docs.libuv.org/en/v1.x/threadpool.html).

Again, conventional wisdom would set the number of threads to the number of CPU
cores, but most operations running in the threadpool are not run hot, they are
not CPU-intensive and block mostly on IO. Issuing more IO operations than there
are CPU cores will increase throughput and will decrease latency per operation
by decreasing queueing time. On the other hand, `@ronomon/crypto-async` is
CPU-intensive. Issuing more `@ronomon/crypto-async` operations than there
are CPU cores will not increase throughput and will increase latency per
operation by increasing queueing time.

You should therefore:

1. Set the threadpool size to `IO` + `N`, where `IO` is the number of filesystem
and DNS operations you expect to be running concurrently, and where `N` is the
number of CPU cores available. This will reduce head-of-line blocking.

2. Allow or design for at most `N` `@ronomon/crypto-async` operations to be
running concurrently, where `N` is the number of CPU cores available. This will
keep latency within reasonable bounds.

```javascript
// At the top of your script, before requiring any modules:
process.env['UV_THREADPOOL_SIZE'] = 128;
```

#### Synchronous method alternatives
All methods have a synchronous method alternative: just leave out the callback
when calling the method. These are convenient for small buffers and outperform the
`crypto` module equivalents.

#### Cipher whitelist
`@ronomon/crypto-async` disables slow, complicated ciphers such as CCM and
[dangerous ciphers](https://blog.cloudflare.com/padding-oracles-and-the-decline-of-cbc-mode-ciphersuites) such as CBC and ECB.
A limited whitelist of stream ciphers and AEAD ciphers are supported. This is a
good thing in the interest of a safe implementation.

##### Supported stream ciphers
These are dangerous if you do not [encrypt-then-mac](http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html):

* **chacha20** (keySize=32, ivSize=16)
* **aes-256-ctr** (keySize=32, ivSize=16)
* **aes-192-ctr** (keySize=24, ivSize=16)
* **aes-128-ctr** (keySize=16, ivSize=16)

##### Supported AEAD ciphers
These are recommended over stream ciphers for safety, ease-of-use and
efficiency:

* **chacha20-poly1305** (keySize=32, ivSize=12, tagSize=16)
* **aes-256-gcm** (keySize=32, ivSize=12, tagSize=16)
* **aes-128-gcm** (keySize=16, ivSize=12, tagSize=16)

#### Cipher
```javascript
var cryptoAsync = require('@ronomon/crypto-async');
var algorithm = 'aes-256-ctr';
var encrypt = 1; // Encrypt
var key = Buffer.alloc(32);
var iv = Buffer.alloc(16);
var plaintext = Buffer.alloc(128);
cryptoAsync.cipher(algorithm, encrypt, key, iv, plaintext,
  function(error, ciphertext) {
    if (error) throw error;
    console.log('ciphertext:', ciphertext.toString('hex'));
    var encrypt = 0; // Decrypt
    cryptoAsync.cipher(algorithm, encrypt, key, iv, ciphertext,
      function(error, plaintext) {
        if (error) throw error;
        console.log('plaintext:', plaintext.toString('hex'));
      }
    );
  }
);
```

#### Cipher (AEAD)
```javascript
var cryptoAsync = require('@ronomon/crypto-async');
var algorithm = 'chacha20-poly1305';
var encrypt = 1; // Encrypt
var key = Buffer.alloc(32);
var iv = Buffer.alloc(12);
var plaintext = Buffer.alloc(128);
var aad = Buffer.alloc(256);
var tag = Buffer.alloc(16);
cryptoAsync.cipher(algorithm, encrypt, key, iv, plaintext, aad, tag,
  function(error, ciphertext) {
    if (error) throw error;
    console.log('ciphertext:', ciphertext.toString('hex'));
    console.log('tag:', tag.toString('hex'));
    var encrypt = 0; // Decrypt
    cryptoAsync.cipher(algorithm, encrypt, key, iv, ciphertext, aad, tag,
      function(error, plaintext) {
        if (error) {
          if (error.message === cryptoAsync.E_CORRUPT) {
            throw new Error('key/iv/source/aad/tag failed authentication');
          } else {
            throw error;
          }
        }
        console.log('plaintext:', plaintext.toString('hex'));
      }
    );
  }
);
```

#### Hash
```javascript
var cryptoAsync = require('@ronomon/crypto-async');
var algorithm = 'sha256';
var source = Buffer.alloc(1024 * 1024);
cryptoAsync.hash(algorithm, source,
  function(error, hash) {
    if (error) throw error;
    console.log('hash:', hash.toString('hex'));
  }
);
```

#### HMAC
```javascript
var cryptoAsync = require('@ronomon/crypto-async');
var algorithm = 'sha256';
var key = Buffer.alloc(1024);
var source = Buffer.alloc(1024 * 1024);
cryptoAsync.hmac(algorithm, key, source,
  function(error, hmac) {
    if (error) throw error;
    console.log('hmac:', hmac.toString('hex'));
  }
);
```

### Zero-Copy Methods

These methods require more arguments but support zero-copy crypto
operations for reduced memory overhead and GC pressure.

#### Cipher (Zero-Copy)
```javascript
var cryptoAsync = require('@ronomon/crypto-async');
var algorithm = 'aes-256-ctr';
var encrypt = 1; // Encrypt
var key = Buffer.alloc(1024);
var keyOffset = 4;
var keySize = 32;
var iv = Buffer.alloc(32);
var ivOffset = 2;
var ivSize = 16;
var source = Buffer.alloc(1024 * 1024);
var sourceOffset = 512;
var sourceSize = 32;
var target = Buffer.alloc(sourceSize + cryptoAsync.CIPHER_BLOCK_MAX);
var targetOffset = 0;
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
  function(error, targetSize) {
    if (error) throw error;
    var slice = target.slice(targetOffset, targetOffset + targetSize);
    console.log('ciphertext:', slice.toString('hex'));
  }
);
```

#### Cipher (Zero-Copy, AEAD)
```javascript
var cryptoAsync = require('@ronomon/crypto-async');
var algorithm = 'chacha20-poly1305';
var encrypt = 1; // Encrypt
var key = Buffer.alloc(1024);
var keyOffset = 4;
var keySize = 32;
var iv = Buffer.alloc(32);
var ivOffset = 2;
var ivSize = 12;
var source = Buffer.alloc(1024 * 1024);
var sourceOffset = 512;
var sourceSize = 32;
var target = Buffer.alloc(sourceSize + cryptoAsync.CIPHER_BLOCK_MAX);
var targetOffset = 0;
var aad = Buffer.alloc(1024);
var aadOffset = 0;
var aadSize = 10;
var tag = Buffer.alloc(16);
var tagOffset = 0;
var tagSize = 16;
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
  aad,
  aadOffset,
  aadSize,
  tag,
  tagOffset,
  tagSize,
  function(error, targetSize) {
    if (error) {
      if (error.message === cryptoAsync.E_CORRUPT) {
        throw new Error('key/iv/source/aad/tag failed authentication');
      } else {
        throw error;
      }
    }
    var slice = target.slice(targetOffset, targetOffset + targetSize);
    console.log('ciphertext:', slice.toString('hex'));
    console.log('tag:', tag.toString('hex', tagOffset, tagOffset + tagSize));
  }
);
```

#### Hash (Zero-Copy)
```javascript
var cryptoAsync = require('@ronomon/crypto-async');
var algorithm = 'sha256';
var source = Buffer.alloc(1024 * 1024);
var sourceOffset = 512;
var sourceSize = 65536;
var target = Buffer.alloc(1024 * 1024);
var targetOffset = 32768;
cryptoAsync.hash(
  algorithm,
  source,
  sourceOffset,
  sourceSize,
  target,
  targetOffset,
  function(error, targetSize) {
    if (error) throw error;
    var slice = target.slice(targetOffset, targetOffset + targetSize);
    console.log('hash:', slice.toString('hex'));
  }
);
```

#### HMAC (Zero-Copy)
```javascript
var cryptoAsync = require('@ronomon/crypto-async');
var algorithm = 'sha256';
var key = Buffer.alloc(1024);
var keyOffset = 4;
var keySize = 8;
var source = Buffer.alloc(1024 * 1024);
var sourceOffset = 512;
var sourceSize = 65536;
var target = Buffer.alloc(1024 * 1024);
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
  function(error, targetSize) {
    if (error) throw error;
    var slice = target.slice(targetOffset, targetOffset + targetSize);
    console.log('hmac:', slice.toString('hex'));
  }
);
```

## Tests
`@ronomon/crypto-async` ships with comprehensive fuzz tests, which have
uncovered multiple bugs in OpenSSL:

* [CVE-2019-1543: chacha20-poly1305 fails to detect IV tampering, where IV > 12 and IV <= CHACHA_CTR_SIZE](https://www.openssl.org/news/secadv/20190306.txt)

* [EVP_CTRL_AEAD_SET_TAG fails for OCB](https://github.com/openssl/openssl/issues/8331)

* [AEAD: EVP_CIPHER_CTX_iv_length is oblivious to EVP_CTRL_AEAD_SET_IVLEN](https://github.com/openssl/openssl/issues/8330)

* [EVP_CipherUpdate() setting AAD for AES-256-OCB returns incorrect `outlen`](https://github.com/openssl/openssl/issues/8310)

To run the tests:
```
node test.js
```

## Benchmark
To benchmark `@ronomon/crypto-async` vs Node's `crypto`:
```
node benchmark.js
```
