const Node = {
  crypto: require('crypto'),
  process: process
};

const BUFFER_EMPTY = Buffer.alloc(0);
const CIPHER_BLOCK_MAX = 32;

const assert = require('assert');
const seed = Math.floor(Math.random() * Math.pow(2, 32));

const random = (function() {
  var key = Buffer.alloc(32, 0);
  key.writeUInt32LE(seed, 0);
  var iv = Buffer.alloc(16);
  var cipher = Node.crypto.createCipheriv('aes-256-ctr', key, iv);
  var buffer;
  var offset;
  var denominator = Math.pow(2, 32);
  return function() {
    if (!buffer || offset + 4 > buffer.length) {
      buffer = cipher.update(Buffer.alloc(65536));
      offset = 0;
    }
    var numerator = buffer.readUInt32LE(offset);
    offset += 4;
    return numerator / denominator;
  };
})();

const randomBuffer = (function() {
  var key = Buffer.alloc(32, 255);
  key.writeUInt32LE(seed, 0);
  var iv = Buffer.alloc(16);
  var cipher = Node.crypto.createCipheriv('aes-256-ctr', key, iv);
  var buffer = Buffer.alloc(1024 * 1024);
  return function(size) {
    if (size <= buffer.length) {
      return cipher.update(buffer.slice(0, size));
    } else {
      return cipher.update(Buffer.alloc(size));
    }
  };
})();

function randomElement(array) {
  return array[Math.floor(random() * array.length)];
}

function randomSize() {
  if (random() < 0.05) return Math.floor(random() * 64);
  if (random() < 0.05) return 0;
  if (random() < 0.1) return Math.floor(random() * 524288);
  return Math.floor(random() * 1024);
}

const Cipher = {
  algorithm: [
    { name: 'aes-128-ctr', keySize: 16, ivSize: 16, tagSize: 0 },
    { name: 'aes-192-ctr', keySize: 24, ivSize: 16, tagSize: 0 },
    { name: 'aes-256-ctr', keySize: 32, ivSize: 16, tagSize: 0 },

    { name: 'aes-128-gcm', keySize: 16, ivSize: 12, tagSize: 16 },
    { name: 'aes-256-gcm', keySize: 32, ivSize: 12, tagSize: 16 }
  ],

  parameters: function() {
    var self = this;
    var algorithm = randomElement(self.algorithm);
    var aead = algorithm.tagSize > 0;
    var encrypt = 1;
    var keySize = algorithm.keySize;
    var ivSize = algorithm.ivSize;
    if (aead) {
      ivSize = Math.ceil(random() * algorithm.ivSize);
      // For ChaCha20-Poly1305, GCM and OCB, all with 12-byte IVs, this can
      // test the upper limit of 16-bytes, 16-bytes and 15-bytes respectively:
      // We disabled this test when it discovered the ChaCha20-Poly1305 CVE.
      // Our binding now prohibits more than 96-bits for any of these ciphers.
      // if (algorithm.ivSize === 12 && random() < 0.5) {
      //   ivSize += (/-ocb$/i.test(algorithm.name) ? 3 : 4);
      // }
    }
    var sourceSize = randomSize();
    var targetSize = sourceSize + CIPHER_BLOCK_MAX;
    var aadSize = 0;
    var tagSize = algorithm.tagSize;
    if (aead) {
      aadSize = randomSize();
      tagSize = tagSize - 4 + Math.round(random() * 4);
      // Leave enough entropy in tag (at least 96 bits) to detect corruption:
      assert(tagSize >= 12);
    }
    if (random() < 0.5) {
      var key = randomBuffer(keySize);
      var iv = randomBuffer(ivSize);
      var source = randomBuffer(sourceSize);
      if (aead || random() < 0.5) {
        var aad = randomBuffer(aadSize);
        var tag = randomBuffer(tagSize);
        return [
          algorithm.name,
          encrypt,
          key,
          iv,
          source,
          aad,
          tag
        ];
      } else {
        return [
          algorithm.name,
          encrypt,
          key,
          iv,
          source
        ];
      }
    } else {
      var keyOffset = randomSize();
      var ivOffset = randomSize();
      var sourceOffset = randomSize();
      var targetOffset = randomSize();
      var key = randomBuffer(keyOffset + keySize + randomSize());
      var iv = randomBuffer(ivOffset + ivSize + randomSize());
      var source = randomBuffer(sourceOffset + sourceSize + randomSize());
      var target = randomBuffer(targetOffset + targetSize + randomSize());
      if (aead || random() < 0.5) {
        var aadOffset = randomSize();
        var tagOffset = randomSize();
        var aad = randomBuffer(aadOffset + aadSize + randomSize());
        var tag = randomBuffer(tagOffset + tagSize + randomSize());
        return [
          algorithm.name,
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
          tagSize
        ];
      } else {
        return [
          algorithm.name,
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
          targetOffset
        ];
      }
    }
  },

  signatures: [
    [
      'algorithm',
      'encrypt',
      'key',
      'iv',
      'source'
    ],
    [
      'algorithm',
      'encrypt',
      'key',
      'iv',
      'source',
      'aad',
      'tag'
    ],
    [
      'algorithm',
      'encrypt',
      'key',
      'keyOffset',
      'keySize',
      'iv',
      'ivOffset',
      'ivSize',
      'source',
      'sourceOffset',
      'sourceSize',
      'target',
      'targetOffset'
    ],
    [
      'algorithm',
      'encrypt',
      'key',
      'keyOffset',
      'keySize',
      'iv',
      'ivOffset',
      'ivSize',
      'source',
      'sourceOffset',
      'sourceSize',
      'target',
      'targetOffset',
      'aad',
      'aadOffset',
      'aadSize',
      'tag',
      'tagOffset',
      'tagSize'
    ]
  ]
};

(function() {
  // We support ChaCha20-Poly1305 as of Node 10, except for testing.
  // Node 10 introduces OpenSSL 1.1, which we need for implementation support.
  // Later versions add these to the crypto module, which we need for testing.
  if (/^v\d+\.\d+\./.test(Node.process.version)) {
    var parts = Node.process.version.replace(/^v/, '').split('.');
    var major = parseInt(parts[0], 10);
    var minor = parseInt(parts[1], 10);
    // Disable OCB (patented):
    // if (major > 10 || (major == 10 && minor >= 10)) {
    //   // OCB is supported in Node from v10.10.0:
    //   // https://github.com/nodejs/node/pull/22716
    //   Cipher.algorithm.push(
    //     { name: 'aes-128-ocb', keySize: 16, ivSize: 12, tagSize: 16 }
    //   );
    //   Cipher.algorithm.push(
    //     { name: 'aes-256-ocb', keySize: 32, ivSize: 12, tagSize: 16 }
    //   );
    // }
    if (major > 11 || (major == 11 && minor >= 2)) {
      // ChaCha20-Poly1305 is supported in Node from v11.2.0:
      // https://github.com/nodejs/node/commit/5c596222433166a7c0274251cca1e55f3
      Cipher.algorithm.push(
        { name: 'chacha20-poly1305', keySize: 32, ivSize: 12, tagSize: 16 }
      );
      Cipher.algorithm.push(
        { name: 'chacha20', keySize: 32, ivSize: 16, tagSize: 0 }
      );
    }
  }
})();

const Hash = {
  algorithm: [
    { name: 'md5', targetSize: 16 },
    { name: 'sha1', targetSize: 20 },
    { name: 'sha256', targetSize: 32 },
    { name: 'sha512', targetSize: 64 },
    { name: 'blake2s256', targetSize: 32 },
    { name: 'blake2b512', targetSize: 64 }
  ],

  parameters: function() {
    var self = this;
    var algorithm = randomElement(self.algorithm);
    var sourceSize = randomSize();
    var targetSize = algorithm.targetSize;
    if (random() < 0.5) {
      var source = randomBuffer(sourceSize);
      return [
        algorithm.name,
        source
      ];
    } else {
      var sourceOffset = randomSize();
      var targetOffset = randomSize();
      var source = randomBuffer(sourceOffset + sourceSize + randomSize());
      var target = randomBuffer(targetOffset + targetSize + randomSize());
      return [
        algorithm.name,
        source,
        sourceOffset,
        sourceSize,
        target,
        targetOffset
      ];
    }
  },

  signatures: [
    [
      'algorithm',
      'source'
    ],
    [
      'algorithm',
      'source',
      'sourceOffset',
      'sourceSize',
      'target',
      'targetOffset'
    ]
  ]
};

const HMAC = {
  algorithm: [
    { name: 'md5', targetSize: 16 },
    { name: 'sha1', targetSize: 20 },
    { name: 'sha256', targetSize: 32 },
    { name: 'sha512', targetSize: 64 },
    { name: 'blake2s256', targetSize: 32 },
    { name: 'blake2b512', targetSize: 64 }
  ],

  parameters: function() {
    var self = this;
    var algorithm = randomElement(self.algorithm);
    var keySize = randomSize();
    var sourceSize = randomSize();
    var targetSize = algorithm.targetSize;
    if (random() < 0.5) {
      var key = randomBuffer(keySize);
      var source = randomBuffer(sourceSize);
      return [
        algorithm.name,
        key,
        source
      ];
    } else {
      var keyOffset = randomSize();
      var sourceOffset = randomSize();
      var targetOffset = randomSize();
      var key = randomBuffer(keyOffset + keySize + randomSize());
      var source = randomBuffer(sourceOffset + sourceSize + randomSize());
      var target = randomBuffer(targetOffset + targetSize + randomSize());
      return [
        algorithm.name,
        key,
        keyOffset,
        keySize,
        source,
        sourceOffset,
        sourceSize,
        target,
        targetOffset
      ];
    }
  },

  signatures: [
    [
      'algorithm',
      'key',
      'source'
    ],
    [
      'algorithm',
      'key',
      'keyOffset',
      'keySize',
      'source',
      'sourceOffset',
      'sourceSize',
      'target',
      'targetOffset'
    ]
  ]
};

const Independent = {};

Independent.cipher = function(...args) {
  var self = this;
  if (args.length >= 19) return self.cipherExecute(...args);
  if (args.length >= 5 && args.length <= 8) {
    var target = Buffer.alloc(args[4].length + CIPHER_BLOCK_MAX);
    var aad = args.length >= 7 ? args[5] : BUFFER_EMPTY;
    var tag = args.length >= 7 ? args[6] : BUFFER_EMPTY;
    var params = [
      args[0],        // algorithm
      args[1],        // encrypt
      args[2],        // key
      0,              // keyOffset
      args[2].length, // keySize
      args[3],        // iv
      0,              // ivOffset
      args[3].length, // ivSize
      args[4],        // source
      0,              // sourceOffset
      args[4].length, // sourceSize
      target,         // target
      0,              // targetOffset
      aad,            // aad
      0,              // aadOffset
      aad.length,     // aadSize
      tag,            // tag
      0,              // tagOffset
      tag.length      // tagSize
    ];
    if (args.length === 5 || args.length === 7) {
      var targetSize = self.cipherExecute(...params);
      return target.slice(0, targetSize);
    } else {
      self.cipherExecute(...params,
        function(error, targetSize) {
          var end = args[args.length - 1];
          if (error) return end(error);
          end(undefined, target.slice(0, targetSize));
        }
      );
    }
  } else if (args.length === 13) {
    var params = [...args, BUFFER_EMPTY, 0, 0, BUFFER_EMPTY, 0, 0];
    return self.cipherExecute(...params);
  } else if (args.length === 14) {
    var end = args.pop(); // Remove callback.
    var params = [...args, BUFFER_EMPTY, 0, 0, BUFFER_EMPTY, 0, 0];
    return self.cipherExecute(...params,
      function(error, targetSize) {
        if (error) return end(error);
        end(undefined, targetSize);
      }
    );
  } else {
    throw new Error('unreachable');
  }
};

Independent.cipherExecute = function(...args) {
  if (args.length !== 19 && args.length !== 20) throw new Error('unreachable');
  var algorithm = args[0];
  var encrypt = args[1];
  var key = args[2];
  var keyOffset = args[3];
  var keySize = args[4];
  var iv = args[5];
  var ivOffset = args[6];
  var ivSize = args[7];
  var source = args[8];
  var sourceOffset = args[9];
  var sourceSize = args[10];
  var target = args[11];
  var targetOffset = args[12];
  var aad = args[13];
  var aadOffset = args[14];
  var aadSize = args[15];
  var tag = args[16];
  var tagOffset = args[17];
  var tagSize = args[18];
  // Slice only if necessary to avoid impacting benchmarks:
  if (key.length !== keySize) key = key.slice(keyOffset, keyOffset + keySize);
  if (iv.length !== ivSize) iv = iv.slice(ivOffset, ivOffset + ivSize);
  if (source.length !== sourceSize) {
    source = source.slice(sourceOffset, sourceOffset + sourceSize);
  }
  if (aad.length !== aadSize) aad = aad.slice(aadOffset, aadOffset + aadSize);
  if (tag.length !== tagSize) tag = tag.slice(tagOffset, tagOffset + tagSize);
  var options = {};
  if (tagSize) options.authTagLength = tagSize;
  var method = encrypt === 1 ? 'createCipheriv' : 'createDecipheriv';
  var cipher = Node.crypto[method](algorithm, key, iv, options);
  if (tagSize && !encrypt) {
    // "The decipher.setAuthTag() method must be called before decipher.final()
    // and can only be called once."
    if (tag.length !== tagSize) throw new Error('assumed tag is a slice');
    cipher.setAuthTag(tag);
  }
  if (tagSize) {
    // We call setAAD() if cipher is an AEAD cipher (inferred from tagSize),
    // without regard to aadSize, because we want to test that empty aad buffers
    // (aadSize === 0) are handled the same as by Node.
    // "The cipher.setAAD() method must be called before cipher.update()."
    // "The decipher.setAAD() method must be called before decipher.update()."
    cipher.setAAD(aad);
  }
  var targetSize = 0;
  targetSize += cipher.update(source).copy(target, targetOffset);
  try {
    targetSize += cipher.final().copy(target, targetOffset + targetSize);
  } catch (error) {
    if (error.message === 'Unsupported state or unable to authenticate data') {
      error.message = 'corrupt';
    }
    if (args.length === 19) throw error;
    return args[19](error);
  }
  if (tagSize && encrypt) {
    // "The cipher.getAuthTag() method should only be called after encryption
    // has been completed using the cipher.final() method."
    if (tag.length !== tagSize) throw new Error('assumed tag is a slice');
    cipher.getAuthTag().copy(tag, 0);
  }
  if (args.length === 19) return targetSize;
  args[19](undefined, targetSize);
};

Independent.hash = function(...args) {
  if (args.length === 2 || args.length === 3) {
    var algorithm = args[0];
    var source = args[1];
    var sourceOffset = 0;
    var sourceSize = source.length;
    var target = Buffer.alloc(64);
    var targetOffset = 0;
  } else if (args.length === 6 || args.length === 7) {
    var algorithm = args[0];
    var source = args[1];
    var sourceOffset = args[2];
    var sourceSize = args[3];
    var target = args[4];
    var targetOffset = args[5];
  } else {
    throw new Error('unreachable');
  }
  var hash = Node.crypto.createHash(algorithm);
  hash.update(source.slice(sourceOffset, sourceOffset + sourceSize));
  var targetSize = hash.digest().copy(target, targetOffset);
  if (arguments.length === 2) {
    return target.slice(targetOffset, targetOffset + targetSize);
  } else if (arguments.length === 3) {
    args[2](undefined, target.slice(targetOffset, targetOffset + targetSize));
  } else if (arguments.length === 6) {
    return targetSize;
  } else if (arguments.length === 7) {
    args[6](undefined, targetSize);
  } else {
    throw new Error('unreachable');
  }
};

Independent.hmac = function(...args) {
  if (args.length === 3 || args.length === 4) {
    var algorithm = args[0];
    var key = args[1];
    var keyOffset = 0;
    var keySize = key.length;
    var source = args[2];
    var sourceOffset = 0;
    var sourceSize = source.length;
    var target = Buffer.alloc(64);
    var targetOffset = 0;
  } else if (args.length === 9 || args.length === 10) {
    var algorithm = args[0];
    var key = args[1];
    var keyOffset = args[2];
    var keySize = args[3];
    var source = args[4];
    var sourceOffset = args[5];
    var sourceSize = args[6];
    var target = args[7];
    var targetOffset = args[8];
  } else {
    throw new Error('unreachable');
  }
  var hmac = Node.crypto.createHmac(algorithm, key.slice(keyOffset, keyOffset + keySize));
  hmac.update(source.slice(sourceOffset, sourceOffset + sourceSize));
  var targetSize = hmac.digest().copy(target, targetOffset);
  if (arguments.length === 3) {
    return target.slice(targetOffset, targetOffset + targetSize);
  } else if (arguments.length === 4) {
    args[3](undefined, target.slice(targetOffset, targetOffset + targetSize));
  } else if (arguments.length === 9) {
    return targetSize;
  } else if (arguments.length === 10) {
    args[9](undefined, targetSize);
  } else {
    throw new Error('unreachable');
  }
};

module.exports.CIPHER_BLOCK_MAX = CIPHER_BLOCK_MAX;

module.exports.cipher = Cipher;

module.exports.hash = Hash;

module.exports.hmac = HMAC;

module.exports.independent = Independent;

module.exports.random = random;

module.exports.seed = seed;
