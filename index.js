'use strict';

const binding = require('./binding.node');

const GUARD_PAGE = Buffer.alloc(4096);
const NO_AAD = GUARD_PAGE.slice(0, 0);
const NO_TAG = GUARD_PAGE.slice(0, 0);

if (!Number.isInteger(binding.CIPHER_BLOCK_MAX)) {
  throw new Error('!Number.isInteger(binding.CIPHER_BLOCK_MAX)');
}

for (var key in binding) {
  if (/^[A-Z_]+$/.test(key)) {
    module.exports[key] = binding[key];
  } else if (!/^(cipher|hash|hmac)$/.test(key)) {
    throw new Error('non-whitelisted binding property: ' + key);
  }
}

module.exports.cipher = function(...args) {
  if (args.length === 19 || args.length === 20) return binding.cipher(...args);
  if (args.length >= 5 && args.length <= 8) {
    var algorithm = args[0];
    var encrypt = args[1];
    var key = args[2];
    var iv = args[3];
    var source = args[4];
    if (!Buffer.isBuffer(key)) throw new Error(binding.E_KEY);
    if (!Buffer.isBuffer(iv)) throw new Error(binding.E_IV);
    if (!Buffer.isBuffer(source)) throw new Error(binding.E_SOURCE);
    var target = Buffer.alloc(source.length + binding.CIPHER_BLOCK_MAX);
    var aad = args.length >= 7 ? args[5] : NO_AAD;
    var tag = args.length >= 7 ? args[6] : NO_TAG;
    if (!Buffer.isBuffer(aad)) throw new Error(binding.E_AAD);
    if (!Buffer.isBuffer(tag)) throw new Error(binding.E_TAG);
    var parameters = [
      algorithm,
      encrypt,
      key,
      0,
      key.length,
      iv,
      0,
      iv.length,
      source,
      0,
      source.length,
      target,
      0,
      aad,
      0,
      aad.length,
      tag,
      0,
      tag.length
    ];
    if (args.length === 5 || args.length === 7) {
      return target.slice(0, binding.cipher(...parameters));
    } else if (args.length === 6 || args.length === 8) {
      var end = args[args.length - 1];
      if (typeof end !== 'function') throw new Error(binding.E_CALLBACK);
      return binding.cipher(...parameters,
        function(error, targetSize) {
          if (error) return end(error);
          end(undefined, target.slice(0, targetSize));
        }
      );
    } else {
      // Unreachable. This is defense in depth.
      throw new Error(binding.E_ARGUMENTS);
    }
  } else if (args.length === 13) {
    return binding.cipher(...args, NO_AAD, 0, 0, NO_TAG, 0, 0);
  } else if (args.length === 14) {
    var end = args.pop(); // Remove callback from args.
    if (typeof end !== 'function') throw new Error(binding.E_CALLBACK);
    return binding.cipher(...args, NO_AAD, 0, 0, NO_TAG, 0, 0, end);
  } else {
    throw new Error(binding.E_ARGUMENTS);
  }
};

module.exports.hash = function(...args) {
  if (args.length === 6 || args.length === 7) return binding.hash(...args);
  if (args.length < 2 || args.length > 3) throw new Error(binding.E_ARGUMENTS);
  var algorithm = args[0];
  var source = args[1];
  if (!Buffer.isBuffer(source)) throw new Error(binding.E_SOURCE);
  var target = Buffer.alloc(64); // Support up to 512 bits.
  if (args.length === 2) {
    return target.slice(0, binding.hash(
      algorithm,
      source,
      0,
      source.length,
      target,
      0
    ));
  } else {
    var end = args[args.length - 1];
    if (typeof end !== 'function') throw new Error(binding.E_CALLBACK);
    return binding.hash(
      algorithm,
      source,
      0,
      source.length,
      target,
      0,
      function(error, targetSize) {
        if (error) return end(error);
        end(undefined, target.slice(0, targetSize));
      }
    );
  }
};

module.exports.hmac = function(...args) {
  if (args.length === 9 || args.length === 10) return binding.hmac(...args);
  if (args.length < 3 || args.length > 4) throw new Error(binding.E_ARGUMENTS);
  var algorithm = args[0];
  var key = args[1];
  var source = args[2];
  if (!Buffer.isBuffer(key)) throw new Error(binding.E_KEY);
  if (!Buffer.isBuffer(source)) throw new Error(binding.E_SOURCE);
  var target = Buffer.alloc(64); // Support up to 512 bits.
  if (args.length === 3) {
    return target.slice(0, binding.hmac(
      algorithm,
      key,
      0,
      key.length,
      source,
      0,
      source.length,
      target,
      0
    ));
  } else {
    var end = args[args.length - 1];
    if (typeof end !== 'function') throw new Error(binding.E_CALLBACK);
    return binding.hmac(
      algorithm,
      key,
      0,
      key.length,
      source,
      0,
      source.length,
      target,
      0,
      function(error, targetSize) {
        if (error) return end(error);
        end(undefined, target.slice(0, targetSize));
      }
    );
  }
};

// S.D.G.
