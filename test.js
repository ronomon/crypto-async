var common = require('./common.js');
var binding = require('.');
var Queue = require('ronomon-queue');

var assertEqual = function(key, a, b) {
  try {
    if (a.length !== b.length) throw new Error(key + ' has different length');
    var length = a.length;
    while (length--) {
      if (a[length] !== b[length]) throw new Error(key + ' is different');
    }
  } catch (error) {
    var aString = Buffer.isBuffer(a) ? a.toString('hex') : JSON.stringify(a);
    var bString = Buffer.isBuffer(b) ? b.toString('hex') : JSON.stringify(b);
    console.log(key + ': a: ' + aString);
    console.log(key + ': b: ' + bString);
    throw error;
  }
};

var wrap = function(columns) {
  return columns[0] + ' ' + columns.slice(1).join('\r\n       ') + '\r\n';
};

var Algorithms = {};

Algorithms.Cipher =
Algorithms.CipherEasy = [
  { name: 'AES-128-CBC', keySize: 16, ivSize: 16 },
  { name: 'AES-192-CBC', keySize: 24, ivSize: 16 },
  { name: 'AES-256-CBC', keySize: 32, ivSize: 16 },
  { name: 'AES-128-CTR', keySize: 16, ivSize: 16 },
  { name: 'AES-192-CTR', keySize: 24, ivSize: 16 },
  { name: 'AES-256-CTR', keySize: 32, ivSize: 16 }
];

Algorithms.Hash =
Algorithms.HashEasy =
Algorithms.HMAC =
Algorithms.HMACEasy = [
  { name: 'MD5', targetSize: 16 },
  { name: 'SHA1', targetSize: 20 },
  { name: 'SHA256', targetSize: 32 },
  { name: 'SHA512', targetSize: 64 }
];

var Compare = {};

Compare.Cipher = function(a, b, aTargetSize, bTargetSize) {
  assertEqual('key', a.key, b.key);
  assertEqual('iv', a.iv, b.iv);
  assertEqual('source', a.source, b.source);
  assertEqual('target', a.target, b.target);
  if (aTargetSize !== bTargetSize) {
    throw new Error(
      'aTargetSize=' + aTargetSize + ' !== bTargetSize=' + bTargetSize
    );
  }
};

Compare.CipherEasy = function(a, b, aTarget, bTarget) {
  assertEqual('key', a.key, b.key);
  assertEqual('iv', a.iv, b.iv);
  assertEqual('source', a.source, b.source);
  assertEqual('target', aTarget, bTarget);
};

Compare.Hash = function(a, b, aTargetSize, bTargetSize) {
  assertEqual('source', a.source, b.source);
  assertEqual('target', a.target, b.target);
  if (aTargetSize !== bTargetSize) {
    throw new Error(
      'aTargetSize=' + aTargetSize + ' !== bTargetSize=' + bTargetSize
    );
  }
};

Compare.HashEasy = function(a, b, aTarget, bTarget) {
  assertEqual('source', a.source, b.source);
  assertEqual('target', aTarget, bTarget);
};

Compare.HMAC = function(a, b, aTargetSize, bTargetSize) {
  assertEqual('key', a.key, b.key);
  assertEqual('source', a.source, b.source);
  assertEqual('target', a.target, b.target);
  if (aTargetSize !== bTargetSize) {
    throw new Error(
      'aTargetSize=' + aTargetSize + ' !== bTargetSize=' + bTargetSize
    );
  }
};

Compare.HMACEasy = function(a, b, aTarget, bTarget) {
  assertEqual('key', a.key, b.key);
  assertEqual('source', a.source, b.source);
  assertEqual('target', aTarget, bTarget);
};

var Describe = {};

Describe.Cipher = function(index, vector) {
  console.log(wrap([
    common.pad(index + 1, 6, '0'),
    vector.algorithm,
    // We do not show encrypt because we encrypt and decrypt per test.
    'key=' + vector.key.length,
    'keyOffset=' + vector.keyOffset,
    'keySize=' + vector.keySize,
    'iv=' + vector.iv.length,
    'ivOffset=' + vector.ivOffset,
    'ivSize=' + vector.ivSize,
    'source=' + vector.source.length,
    'sourceOffset=' + vector.sourceOffset,
    'sourceSize=' + vector.sourceSize,
    'target=' + vector.target.length,
    'targetOffset=' + vector.targetOffset
  ]));
};

Describe.CipherEasy = function(index, vector) {
  console.log(wrap([
    common.pad(index + 1, 6, '0'),
    vector.algorithm,
    'key=' + vector.key.length,
    'iv=' + vector.iv.length,
    'source=' + vector.source.length
  ]));
};

Describe.Hash = function(index, vector) {
  console.log(wrap([
    common.pad(index + 1, 6, '0'),
    'HASH-' + vector.algorithm,
    'source=' + vector.source.length,
    'sourceOffset=' + vector.sourceOffset,
    'sourceSize=' + vector.sourceSize,
    'target=' + vector.target.length,
    'targetOffset=' + vector.targetOffset
  ]));
};

Describe.HashEasy = function(index, vector) {
  console.log(wrap([
    common.pad(index + 1, 6, '0'),
    'HASH-' + vector.algorithm,
    'source=' + vector.source.length
  ]));
};

Describe.HMAC = function(index, vector) {
  console.log(wrap([
    common.pad(index + 1, 6, '0'),
    'HMAC-' + vector.algorithm,
    'key=' + vector.key.length,
    'keyOffset=' + vector.keyOffset,
    'keySize=' + vector.keySize,
    'source=' + vector.source.length,
    'sourceOffset=' + vector.sourceOffset,
    'sourceSize=' + vector.sourceSize,
    'target=' + vector.target.length,
    'targetOffset=' + vector.targetOffset
  ]));
};

Describe.HMACEasy = function(index, vector) {
  console.log(wrap([
    common.pad(index + 1, 6, '0'),
    'HMAC-' + vector.algorithm,
    'key=' + vector.key.length,
    'source=' + vector.source.length
  ]));
};

var Execute = {};

Execute.Cipher = function(binding, vector, end) {
  binding.cipher(
    vector.algorithm,
    1,
    vector.key,
    vector.keyOffset,
    vector.keySize,
    vector.iv,
    vector.ivOffset,
    vector.ivSize,
    vector.source,
    vector.sourceOffset,
    vector.sourceSize,
    vector.target,
    vector.targetOffset,
    function(error, targetSize) {
      if (error) return end(error);
      var temp = new Buffer(vector.sourceSize + 128);
      binding.cipher(
        vector.algorithm,
        0,
        vector.key,
        vector.keyOffset,
        vector.keySize,
        vector.iv,
        vector.ivOffset,
        vector.ivSize,
        vector.target,
        vector.targetOffset,
        targetSize,
        temp,
        0,
        function(error, sourceSize) {
          if (error) return end(error);
          temp.copy(vector.source, vector.sourceOffset, 0, sourceSize);
          end();
        }
      );
    }
  );
};

Execute.CipherEasy = function(binding, vector, end) {
  binding.cipher(
    vector.algorithm,
    1,
    vector.key,
    vector.iv,
    vector.source,
    function(error, target) {
      if (error) return end(error);
      binding.cipher(
        vector.algorithm,
        0,
        vector.key,
        vector.iv,
        target,
        function(error, source) {
          if (error) return end(error);
          assertEqual('cipher roundtrip', source, vector.source);
          end(undefined, target);
        }
      );
    }
  );
};

Execute.Hash = function(binding, vector, end) {
  binding.hash(
    vector.algorithm,
    vector.source,
    vector.sourceOffset,
    vector.sourceSize,
    vector.target,
    vector.targetOffset,
    end
  );
};

Execute.HashEasy = function(binding, vector, end) {
  binding.hash(
    vector.algorithm,
    vector.source,
    end
  );
};

Execute.HMAC = function(binding, vector, end) {
  binding.hmac(
    vector.algorithm,
    vector.key,
    vector.keyOffset,
    vector.keySize,
    vector.source,
    vector.sourceOffset,
    vector.sourceSize,
    vector.target,
    vector.targetOffset,
    end
  );
};

Execute.HMACEasy = function(binding, vector, end) {
  binding.hmac(
    vector.algorithm,
    vector.key,
    vector.source,
    end
  );
};

console.log('\r\n  SEED=' + common.seed + '\r\n');

var queue = new Queue(1);
queue.onData = function(test, end) {
  var a = new common.Vector[test.type](Algorithms[test.type], undefined);
  var b = new common.Vector[test.type](Algorithms[test.type], a);
  Describe[test.type](test.index, a);
  Execute[test.type](binding, a,
    function(error, aTargetSize) {
      if (error) return end(error);
      Execute[test.type](common.independent, b,
        function(error, bTargetSize) {
          if (error) return end(error);
          Compare[test.type](a, b, aTargetSize, bTargetSize);
          end();
        }
      );
    }
  );
};
queue.onEnd = function(error) {
  if (error) throw error;
  console.log('PASSED ALL TESTS\r\n');
};
var tests = [];
var index = 0;
var length = 5000;
while (length--) tests.push({ type: 'Cipher', index: index++ });
var length = 5000;
while (length--) tests.push({ type: 'CipherEasy', index: index++ });
var length = 5000;
while (length--) tests.push({ type: 'Hash', index: index++ });
var length = 5000;
while (length--) tests.push({ type: 'HashEasy', index: index++ });
var length = 5000;
while (length--) tests.push({ type: 'HMAC', index: index++ });
var length = 5000;
while (length--) tests.push({ type: 'HMACEasy', index: index++ });
queue.concat(tests);
queue.end();
