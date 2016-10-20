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

independent.cipher = function(
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
  end
) {
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
  end(undefined, buffer.length);
};

independent.hash = function(
  algorithm,
  source,
  sourceOffset,
  sourceSize,
  target,
  targetOffset,
  end
) {
  var hash = crypto.createHash(algorithm);
  hash.update(source.slice(sourceOffset, sourceOffset + sourceSize));
  var targetSize = hash.digest().copy(target, targetOffset);
  end(undefined, targetSize);
};

independent.hmac = function(
  algorithm,
  key,
  keyOffset,
  keySize,
  source,
  sourceOffset,
  sourceSize,
  target,
  targetOffset,
  end
) {
  var hash = crypto.createHmac(algorithm, key.slice(keyOffset, keyOffset + keySize));
  hash.update(source.slice(sourceOffset, sourceOffset + sourceSize));
  var targetSize = hash.digest().copy(target, targetOffset);
  end(undefined, targetSize);
};

var QueueStream = function(concurrent, onEnd) {
  var self = this;
  self.closed = false;
  self.eof = false;
  self.done = false;
  self.arrays = [];
  self.array = undefined;
  self.index = 0;
  self.pending = 0;
  self.running = 0;
  if (concurrent === true) {
    self.concurrent = 1000000;
  } else if (typeof concurrent == 'number') {
    if (Math.floor(concurrent) !== concurrent) {
      throw 'QueueStream: Bad concurrent argument: ' + concurrent;
    }
    self.concurrent = concurrent;
  } else {
    self.concurrent = 1;
  }
  self.processing = false;
  if (onEnd) self.onEnd = onEnd;
};

QueueStream.prototype.callback = function(error) {
  var self = this;
  if (self.closed) return;
  self.running--;
  if (error) {
    self.closed = true;
    self.onEnd(error);
  } else if (self.done) {
    self.closed = true;
    self.onEnd();
  } else if (self.eof && (self.pending + self.running) === 0) {
    self.closed = true;
    self.onEnd();
  } else if (!self.processing) {
    self.process();
  }
};

QueueStream.prototype.clear = function() {
  var self = this;
  self.arrays = [];
  self.array = undefined;
  self.index = 0;
  self.pending = 0;
};

QueueStream.prototype.end = function(error) {
  var self = this;
  if (self.closed) return;
  if (self.eof) return;
  self.eof = true;
  if (error || self.running === 0) {
    self.closed = true;
    self.onEnd(error);
  }
};

QueueStream.prototype.onData = function(data, end) { end(); };

QueueStream.prototype.onEnd = function(error) {};

QueueStream.prototype.process = function() {
  var self = this;
  if (self.processing) return;
  self.processing = true;
  function callback(error) { self.callback(error); }
  do {
    while (self.array && self.index < self.array.length) {
      if (self.closed || self.running >= self.concurrent) {
        return (self.processing = false);
      }
      self.pending--;
      self.running++;
      self.onData(self.array[self.index++], callback);
    }
    self.array = self.arrays.shift();
    self.index = 0;
  } while (self.array);
  self.processing = false;
};

QueueStream.prototype.push = function(data) {
  var self = this;
  if (self.closed) return;
  if (!data || data.constructor !== Array) {
    data = [data];
  } else if (data.length === 0) {
    return;
  }
  if (self.array) {
    self.arrays.push(data);
  } else {
    self.array = data;
  }
  self.pending += data.length;
  if (!self.processing) self.process();
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

module.exports.evaluateRNG = evaluateRNG;

module.exports.independent = independent;

module.exports.pad = function(string, width, padding) {
  if (typeof string != 'string') string = String(string);
  while (string.length < width) string = padding + string;
  return string;
};

module.exports.QueueStream = QueueStream;

module.exports.RNG = RNG;

module.exports.seed = rng.seed;

module.exports.Vector = Vector;
