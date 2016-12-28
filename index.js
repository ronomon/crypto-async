'use strict';

var binding = require('./build/Release/binding.node');

module.exports.cipher = function() {
  if (arguments.length === 14) return binding.cipher.apply(this, arguments);
  if (arguments.length !== 6) throw new Error('bad number of arguments');
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
  var target = Buffer.alloc(sourceSize + 64);
  var targetOffset = 0;
  var end = arguments[5];
  binding.cipher(
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
      if (error) return end(error);
      end(undefined, target.slice(targetOffset, targetOffset + targetSize));
    }
  );
};

module.exports.hash = function() {
  if (arguments.length === 7) return binding.hash.apply(this, arguments);
  if (arguments.length !== 3) throw new Error('bad number of arguments');
  var algorithm = arguments[0];
  var source = arguments[1];
  var sourceOffset = 0;
  var sourceSize = source.length;
  var target = Buffer.alloc(64); // Support up to 512 bits.
  var targetOffset = 0;
  var end = arguments[2];
  binding.hash(
    algorithm,
    source,
    sourceOffset,
    sourceSize,
    target,
    targetOffset,
    function(error, targetSize) {
      if (error) return end(error);
      end(undefined, target.slice(targetOffset, targetOffset + targetSize));
    }
  );
};

module.exports.hmac = function() {
  if (arguments.length === 10) return binding.hmac.apply(this, arguments);
  if (arguments.length !== 4) throw new Error('bad number of arguments');
  var algorithm = arguments[0];
  var key = arguments[1];
  var keyOffset = 0;
  var keySize = key.length;
  var source = arguments[2];
  var sourceOffset = 0;
  var sourceSize = source.length;
  var target = Buffer.alloc(64); // Support up to 512 bits.
  var targetOffset = 0;
  var end = arguments[3];
  binding.hmac(
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
      if (error) return end(error);
      end(undefined, target.slice(targetOffset, targetOffset + targetSize));
    }
  );
};

// S.D.G.
