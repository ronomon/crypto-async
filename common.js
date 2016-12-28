var crypto = require('crypto');

var RNG = function(seed) {
  var self = this;
  if (seed === undefined) seed = Date.now();
  if (typeof seed !== 'number' || Math.round(seed) !== seed || seed < 0) {
    throw new Error('bad seed');
  }
  self.seed = seed % Math.pow(2, 31);
  self.hash = self.seed;
};

RNG.prototype.random = function() {
  var self = this;
  self.hash = ((self.hash + 0x7ED55D16) + (self.hash << 12)) & 0xFFFFFFF;
  self.hash = ((self.hash ^ 0xC761C23C) ^ (self.hash >>> 19)) & 0xFFFFFFF;
  self.hash = ((self.hash + 0x165667B1) + (self.hash << 5)) & 0xFFFFFFF;
  self.hash = ((self.hash + 0xD3A2646C) ^ (self.hash << 9)) & 0xFFFFFFF;
  self.hash = ((self.hash + 0xFD7046C5) + (self.hash << 3)) & 0xFFFFFFF;
  self.hash = ((self.hash ^ 0xB55A4F09) ^ (self.hash >>> 16)) & 0xFFFFFFF;
  return (self.hash & 0xFFFFFFF) / 0x10000000;
};

var evaluateRNG = function() {
  var rng = new RNG();
  console.log('Evaluating random numbers for seed ' + rng.seed + '...');
  var seen = {};
  var count = 0;
  while (++count) {
    var value = rng.random();
    if (typeof value != 'number') {
      throw new Error('Detected bad value: ' + value);
    }
    if (value < 0 || value >= 1) {
      throw new Error('Detected out of bounds value: ' + value);
    }
    if (seen.hasOwnProperty(value)) {
      throw new Error('Detected wraparound after ' + count + ' number(s).');
    }
    if (count >= 10000000) {
      return console.log('Generated ' + count + ' numbers without wraparound.');
    }
    seen[value] = 1;
  }
};

var rng = new RNG();
var random = rng.random.bind(rng);

var independent = {};

independent.cipher = function() {
  if (arguments.length === 6) {
    var algorithm = arguments[0];
    var encrypt = arguments[1];
    var key = arguments[2];
    var keyOffset = 0;
    var keySize = key.length;
    var iv = arguments[3];
    var ivOffset = 0;
    var ivSize = iv.length;
    var source = arguments[4];
    var sourceOffset = 0;
    var sourceSize = source.length;
    var target = Buffer.alloc(sourceSize + 128);
    var targetOffset = 0;
    var end = arguments[5];
  } else {
    var algorithm = arguments[0];
    var encrypt = arguments[1];
    var key = arguments[2];
    var keyOffset = arguments[3];
    var keySize = arguments[4];
    var iv = arguments[5];
    var ivOffset = arguments[6];
    var ivSize = arguments[7];
    var source = arguments[8];
    var sourceOffset = arguments[9];
    var sourceSize = arguments[10];
    var target = arguments[11];
    var targetOffset = arguments[12];
    var end = arguments[13];
  }
  var cipher = crypto[encrypt == 1 ? 'createCipheriv' : 'createDecipheriv'](
    algorithm,
    key.slice(keyOffset, keyOffset + keySize),
    iv.slice(ivOffset, ivOffset + ivSize)
  );
  var buffer = Buffer.concat([
    cipher.update(source.slice(sourceOffset, sourceOffset + sourceSize)),
    cipher.final()
  ]);
  buffer.copy(target, targetOffset);
  if (arguments.length === 6) {
    end(undefined, buffer);
  } else {
    end(undefined, buffer.length);
  }
};

independent.hash = function() {
  if (arguments.length === 3) {
    var algorithm = arguments[0];
    var source = arguments[1];
    var sourceOffset = 0;
    var sourceSize = source.length;
    var target = Buffer.alloc(128);
    var targetOffset = 0;
    var end = arguments[2];
  } else {
    var algorithm = arguments[0];
    var source = arguments[1];
    var sourceOffset = arguments[2];
    var sourceSize = arguments[3];
    var target = arguments[4];
    var targetOffset = arguments[5];
    var end = arguments[6];
  }
  var hash = crypto.createHash(algorithm);
  hash.update(source.slice(sourceOffset, sourceOffset + sourceSize));
  var targetSize = hash.digest().copy(target, targetOffset);
  if (arguments.length === 3) {
    end(undefined, target.slice(targetOffset, targetOffset + targetSize));
  } else {
    end(undefined, targetSize);
  }
};

independent.hmac = function() {
  if (arguments.length === 4) {
    var algorithm = arguments[0];
    var key = arguments[1];
    var keyOffset = 0;
    var keySize = key.length;
    var source = arguments[2];
    var sourceOffset = 0;
    var sourceSize = source.length;
    var target = Buffer.alloc(128);
    var targetOffset = 0;
    var end = arguments[3];
  } else {
    var algorithm = arguments[0];
    var key = arguments[1];
    var keyOffset = arguments[2];
    var keySize = arguments[3];
    var source = arguments[4];
    var sourceOffset = arguments[5];
    var sourceSize = arguments[6];
    var target = arguments[7];
    var targetOffset = arguments[8];
    var end = arguments[9];
  }
  var hmac = crypto.createHmac(algorithm, key.slice(keyOffset, keyOffset + keySize));
  hmac.update(source.slice(sourceOffset, sourceOffset + sourceSize));
  var targetSize = hmac.digest().copy(target, targetOffset);
  if (arguments.length === 4) {
    end(undefined, target.slice(targetOffset, targetOffset + targetSize));
  } else {
    end(undefined, targetSize);
  }
};

function copyBuffer(buffer) {
  var copy = new Buffer(buffer.length);
  buffer.copy(copy, 0);
  return copy;
}

function randomBuffer(size) {
  var buffer = new Buffer(size);
  buffer.fill(Math.floor(random() * 256));
  return buffer;
}

function randomSize() {
  if (random() < 0.05) return Math.floor(random() * 64);
  if (random() < 0.05) return 0;
  if (random() < 0.1) return Math.floor(random() * 524288);
  return Math.floor(random() * 1024);
}

var Vector = {};

Vector.Cipher = function(algorithms, a, sourceSize) {
  var self = this;
  if (a) {
    self.algorithm = a.algorithm;
    self.encrypt = a.encrypt;
    self.key = copyBuffer(a.key);
    self.keyOffset = a.keyOffset;
    self.keySize = a.keySize;
    self.iv = copyBuffer(a.iv);
    self.ivOffset = a.ivOffset;
    self.ivSize = a.ivSize;
    self.source = copyBuffer(a.source);
    self.sourceOffset = a.sourceOffset;
    self.sourceSize = a.sourceSize;
    self.target = copyBuffer(a.target);
    self.targetOffset = a.targetOffset;
  } else if (typeof sourceSize == 'number') {
    var algorithm = algorithms[0];
    self.algorithm = algorithm.name;
    self.encrypt = 1;
    self.key = randomBuffer(algorithm.keySize);
    self.keyOffset = 0;
    self.keySize = self.key.length;
    self.iv = randomBuffer(algorithm.ivSize);
    self.ivOffset = 0;
    self.ivSize = self.iv.length;
    self.source = randomBuffer(sourceSize);
    self.sourceOffset = 0;
    self.sourceSize = self.source.length;
    self.target = randomBuffer(self.source.length + 128);
    self.targetOffset = 0;
  } else {
    var algorithm = algorithms[Math.floor(random() * algorithms.length)];
    self.algorithm = algorithm.name;
    self.encrypt = 1;
    var keyLength = randomSize() + algorithm.keySize;
    var ivLength = randomSize() + algorithm.ivSize;
    var sourceLength = randomSize();
    var targetLength = randomSize() + sourceLength + 128;
    self.key = randomBuffer(keyLength);
    self.keyOffset = Math.floor(random() * (keyLength - algorithm.keySize));
    self.keySize = algorithm.keySize;
    self.iv = randomBuffer(ivLength);
    self.ivOffset = Math.floor(random() * (ivLength - algorithm.ivSize));
    self.ivSize = algorithm.ivSize;
    self.source = randomBuffer(sourceLength);
    self.sourceOffset = Math.floor(random() * sourceLength);
    self.sourceSize = Math.floor(random() * (sourceLength - self.sourceOffset));
    self.target = randomBuffer(targetLength);
    self.targetOffset = Math.floor(random() * (targetLength - sourceLength - 128));
  }
};

Vector.CipherEasy = function(algorithms, a, sourceSize) {
  var self = this;
  if (a) {
    self.algorithm = a.algorithm;
    self.encrypt = a.encrypt;
    self.key = copyBuffer(a.key);
    self.iv = copyBuffer(a.iv);
    self.source = copyBuffer(a.source);
  } else if (typeof sourceSize == 'number') {
    var algorithm = algorithms[0];
    self.algorithm = algorithm.name;
    self.encrypt = 1;
    self.key = randomBuffer(algorithm.keySize);
    self.iv = randomBuffer(algorithm.ivSize);
    self.source = randomBuffer(sourceSize);
  } else {
    var algorithm = algorithms[Math.floor(random() * algorithms.length)];
    self.algorithm = algorithm.name;
    self.encrypt = 1;
    self.key = randomBuffer(algorithm.keySize);
    self.iv = randomBuffer(algorithm.ivSize);
    self.source = randomBuffer(randomSize());
  }
};

Vector.Hash = function(algorithms, a, sourceSize) {
  var self = this;
  if (a) {
    self.algorithm = a.algorithm;
    self.source = copyBuffer(a.source);
    self.sourceOffset = a.sourceOffset;
    self.sourceSize = a.sourceSize;
    self.target = copyBuffer(a.target);
    self.targetOffset = a.targetOffset;
  } else if (typeof sourceSize == 'number') {
    var algorithm = algorithms[0];
    self.algorithm = algorithm.name;
    self.source = randomBuffer(sourceSize);
    self.sourceOffset = 0;
    self.sourceSize = self.source.length;
    self.target = randomBuffer(algorithm.targetSize);
    self.targetOffset = 0;
  } else {
    var algorithm = algorithms[Math.floor(random() * algorithms.length)];
    self.algorithm = algorithm.name;
    var sourceLength = randomSize();
    var targetLength = randomSize() + algorithm.targetSize;
    self.source = randomBuffer(sourceLength);
    self.sourceOffset = Math.floor(random() * sourceLength);
    self.sourceSize = Math.floor(random() * (sourceLength - self.sourceOffset));
    self.target = randomBuffer(targetLength);
    self.targetOffset = Math.floor(random() * (targetLength - algorithm.targetSize));
  }
};

Vector.HashEasy = function(algorithms, a, sourceSize) {
  var self = this;
  if (a) {
    self.algorithm = a.algorithm;
    self.source = copyBuffer(a.source);
  } else if (typeof sourceSize == 'number') {
    var algorithm = algorithms[0];
    self.algorithm = algorithm.name;
    self.source = randomBuffer(sourceSize);
  } else {
    var algorithm = algorithms[Math.floor(random() * algorithms.length)];
    self.algorithm = algorithm.name;
    self.source = randomBuffer(randomSize());
  }
};

Vector.HMAC = function(algorithms, a, sourceSize) {
  var self = this;
  if (a) {
    self.algorithm = a.algorithm;
    self.key = copyBuffer(a.key);
    self.keyOffset = a.keyOffset;
    self.keySize = a.keySize;
    self.source = copyBuffer(a.source);
    self.sourceOffset = a.sourceOffset;
    self.sourceSize = a.sourceSize;
    self.target = copyBuffer(a.target);
    self.targetOffset = a.targetOffset;
  } else if (typeof sourceSize == 'number') {
    var algorithm = algorithms[0];
    self.algorithm = algorithm.name;
    self.key = randomBuffer(algorithm.targetSize);
    self.keyOffset = 0;
    self.keySize = self.key.length;
    self.source = randomBuffer(sourceSize);
    self.sourceOffset = 0;
    self.sourceSize = self.source.length;
    self.target = randomBuffer(algorithm.targetSize);
    self.targetOffset = 0;
  } else {
    var algorithm = algorithms[Math.floor(random() * algorithms.length)];
    self.algorithm = algorithm.name;
    var keyLength = randomSize();
    var sourceLength = randomSize();
    var targetLength = randomSize() + algorithm.targetSize;
    self.key = randomBuffer(keyLength);
    self.keyOffset = Math.floor(random() * keyLength);
    self.keySize = Math.floor(random() * (keyLength - self.keyOffset));
    self.source = randomBuffer(sourceLength);
    self.sourceOffset = Math.floor(random() * sourceLength);
    self.sourceSize = Math.floor(random() * (sourceLength - self.sourceOffset));
    self.target = randomBuffer(targetLength);
    self.targetOffset = Math.floor(random() * (targetLength - algorithm.targetSize));
  }
};

Vector.HMACEasy = function(algorithms, a, sourceSize) {
  var self = this;
  if (a) {
    self.algorithm = a.algorithm;
    self.key = copyBuffer(a.key);
    self.source = copyBuffer(a.source);
  } else if (typeof sourceSize == 'number') {
    var algorithm = algorithms[0];
    self.algorithm = algorithm.name;
    self.key = randomBuffer(algorithm.targetSize);
    self.source = randomBuffer(sourceSize);
  } else {
    var algorithm = algorithms[Math.floor(random() * algorithms.length)];
    self.algorithm = algorithm.name;
    self.key = randomBuffer(randomSize());
    self.source = randomBuffer(randomSize());
  }
};

module.exports.evaluateRNG = evaluateRNG;

module.exports.independent = independent;

module.exports.pad = function(string, width, padding) {
  if (typeof string != 'string') string = String(string);
  while (string.length < width) string = padding + string;
  return string;
};

module.exports.RNG = RNG;

module.exports.seed = rng.seed;

module.exports.Vector = Vector;
