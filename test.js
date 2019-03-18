var assert = require('assert');
var binding = require('.');
var common = require('./common.js');
var Queue = require('@ronomon/queue');

function Bad(a, b, offset, size) {
  // Corrupt two buffers for testing AEAD authentication:
  if (offset === undefined) offset = 0;
  if (size === undefined) size = a.length;
  if (size === 0) return 0;
  var corruptOffset = offset + Math.floor(common.random() * size);
  a[corruptOffset] = (a[corruptOffset] + 1) & 255;
  b[corruptOffset] = (b[corruptOffset] + 1) & 255;
  a.corrupt = true;
  b.corrupt = true;
  return 1;
}

function Compare(test, a, b, key) {
  try {
    if (a.length !== b.length) {
      throw new Error(
        key + ': a.length !== b.length (' + a.length + ' !== ' + b.length + ')'
      );
    }
    for (var index = 0, length = a.length; index < length; index++) {
      var x = a[index];
      var y = b[index];
      if (
        typeof x === 'string' || typeof x === 'number' || x === undefined ||
        typeof y === 'string' || typeof y === 'number' || y === undefined
      ) {
        if (x !== y) {
          throw new Error(
            key + '[' + index + ']: ' +
            JSON.stringify(x) + ' !== ' + JSON.stringify(y)
          );
        }
      } else if (Buffer.isBuffer(x)) {
        if (!Buffer.isBuffer(y)) {
          console.log('a: ' + x.toString('hex'));
          console.log('b: ' + JSON.stringify(y));
          throw new Error(key + '[' + index + ']: ' + 'buffer vs non-buffer');
        }
        if (!x.equals(y)) {
          if (
            test.method === 'cipher' &&
            key === 'arguments' &&
            index === 11 &&
            x.different === true &&
            y.different === true
          ) {
            continue;
          }
          throw new Error(key + '[' + index + ']: ' + 'buffers are different');
        }
      } else if (x instanceof Error) {
        if (!(y instanceof Error)) {
          console.log('a:', x);
          console.log('b:', y);
          throw new Error(key + '[' + index + ']: ' + 'error vs non-error');
        }
        if (x.toString() !== y.toString()) {
          console.log('a:', x);
          console.log('b:', y);
          throw new Error(key + '[' + index + ']: ' + 'errors are different');
        }
      } else {
        console.log(x);
        console.log(y);
        throw new Error(key + '[' + index + ']: ' + 'unsupported type');
      }
    }
  } catch (exception) {
    console.log('');
    console.log('Failed test ' + test.number.toString().padStart(6, '0') + ':');
    console.log('');
    throw exception;
  }
}

function Copy(parameters) {
  return parameters.map(
    function(parameter) {
      if (typeof parameter === 'number') return parameter;
      if (typeof parameter === 'string') return parameter;
      if (Buffer.isBuffer(parameter)) return Buffer.from(parameter);
      console.log(parameter);
      throw new Error('unsupported parameter type');
    }
  );
}

function Execute(test, parameters, engine, end) {
  if (test.sync) {
    try {
      var result = engine[test.method].apply(engine, parameters);
    } catch (exception) {
      return end(exception);
    }
    end(undefined, result);
  } else {
    engine[test.method].apply(engine, parameters.concat(end));
  }
}

function Inspect(test, parameters) {
  var tuples;
  common[test.method].signatures.some(
    function(signature) {
      if (signature.length !== parameters.length) return false;
      tuples = [];
      signature.forEach(
        function(key, index) {
          var value = parameters[index];
          if (Buffer.isBuffer(value)) {
            var corrupt = '';
            if (test.method === 'cipher' && value.corrupt) {
              corrupt = ' [corrupt]';
            }
            tuples.push(key + '=' + value.length + corrupt);
          } else {
            tuples.push(key + '=' + value);
          }
        }
      );
      return true;
    }
  );
  if (!tuples) throw new Error('unsupported parameters signature');
  var sync = test.sync ? ' sync' : '';
  tuples.unshift(test.method + '()' + sync);
  tuples.unshift(test.number.toString().padStart(6, '0'));
  console.log(tuples[0] + ' ' + tuples.slice(1).join('\r\n       ') + '\r\n');
}

function Probe(method, signature, algorithm) {
  // First, generate valid signature arguments, which we can then corrupt:
  const args = [];
  // We use maxInt, maxOffset and maxSize to test range checks:
  const maxInt = 2147483647;
  // We must provide exact-sized keys, IVs and tags for simple signatures:
  // We don't do range checks for simple signatures.
  const maxOffset = signature.indexOf('target') === -1 ? 0 : 1;
  const maxSize = 256;
  signature.forEach(
    function(key, index) {
      switch (key) {
      case 'algorithm':
        return args.push(algorithm.name);
      case 'encrypt':
        return args.push(0);
      case 'key':
        return args.push(Buffer.alloc(maxOffset + (algorithm.keySize || 32)));
      case 'source':
      case 'aad':
        return args.push(Buffer.alloc(maxOffset + maxSize));
      case 'target':
        if (method === 'cipher') {
          return args.push(Buffer.alloc(maxOffset + maxSize + 32));
        } else {
          return args.push(Buffer.alloc(maxOffset + maxSize));
        }
      case 'iv':
        return args.push(Buffer.alloc(maxOffset + algorithm.ivSize));
      case 'tag':
        // The extra byte is used to test E_TAG_INVALID for non-AEAD ciphers:
        return args.push(Buffer.alloc(maxOffset + algorithm.tagSize + 1));
      case 'keyOffset':
      case 'ivOffset':
      case 'sourceOffset':
      case 'targetOffset':
      case 'aadOffset':
      case 'tagOffset':
        return args.push(maxOffset);
      case 'keySize':
      case 'ivSize':
      case 'sourceSize':
        var buffer = args[index - 2];
        assert(Buffer.isBuffer(buffer));
        return args.push(buffer.length - maxOffset);
      case 'aadSize':
        return args.push(algorithm.tagSize ? maxSize : 0);
      case 'tagSize':
        return args.push(algorithm.tagSize);
      }
      throw new Error('unsupported signature key: ' + key);
    }
  );

  // Next, corrupt these valid arguments:
  const map = [];
  const nonInt = [
    -Infinity,
    Infinity,
    NaN,
    -1,
    0.0000001,
    1.0000001,
    '',
    {},
    [],
    null,
    true,
    false,
    undefined,
    Buffer.alloc(0),
    -Math.pow(2, 53),
    Math.pow(2, 53)
  ];
  
  // Wrong number of arguments:
  // Cipher method signatures may overlap.
  map.push([[], 'E_ARGUMENTS']);
  if (method !== 'cipher' || args.length === 5) {
    map.push([args.slice(1), 'E_ARGUMENTS']);
  }
  if (method !== 'cipher' || args.length === 7) {
    map.push([[...args, function() {}, null], 'E_ARGUMENTS']);
  }
  
  // AEAD ciphers must always provide a tag:
  // If the signature is not an AEAD signature then index.js should pass NO_TAG.
  // The binding must then throw E_TAG_INVALID.
  if (
    method === 'cipher' &&
    algorithm.tagSize > 0 &&
    signature.indexOf('tag') === -1
  ) {
    assert(signature.indexOf('aad') === -1);
    assert(signature.length === 5 || signature.length === 13);
    map.push([args, 'E_TAG_INVALID']);
    map.push([args, 'E_TAG_INVALID']);
  }
  
  // Bad callbacks:
  map.push([[...args, 0], 'E_CALLBACK']);
  map.push([[...args, 1], 'E_CALLBACK']);
  map.push([[...args, {}], 'E_CALLBACK']);
  map.push([[...args, null], 'E_CALLBACK']);
  map.push([[...args, undefined], 'E_CALLBACK']);

  signature.forEach(
    function(key, index) {
      function check(code, values) {
        values.forEach(
          function(value) {
            var copy = args.slice(0);
            copy[index] = value;
            map.push([copy, code]);
          }
        );
      }
      switch (key) {
      case 'algorithm':
        check('E_ALGORITHM', [
          0,
          {},
          null,
          true,
          false,
          undefined,
          Buffer.alloc(0)
        ]);
        if (method === 'cipher') {
          // These are a subset of disabled ciphers:
          check('E_ALGORITHM_DISABLED', [
            'aes-128-cbc',
            'aes-192-cbc',
            'aes-256-cbc',

            'aes-128-ccm',
            'aes-192-ccm',
            'aes-256-ccm',

            'aes-128-ecb',
            'aes-192-ecb',
            'aes-256-ecb',

            'aes-128-xts',
            'aes-256-xts',

            'rc4'
          ]);
        }
        return check('E_ALGORITHM_UNKNOWN', ['', 'unknown']);
      case 'encrypt':
        return check('E_ENCRYPT', nonInt);
      case 'key':
      case 'iv':
      case 'source':
      case 'target':
      case 'aad':
      case 'tag':
        return check('E_' + key.toUpperCase(), [
          0,
          1,
          '',
          {},
          [],
          null,
          true,
          false,
          undefined
        ]);
      case 'keyOffset':
      case 'keySize':
      case 'ivOffset':
      case 'ivSize':
      case 'sourceOffset':
      case 'sourceSize':
      case 'targetOffset':
      case 'aadOffset':
      case 'aadSize':
      case 'tagOffset':
      case 'tagSize':
        assert(maxOffset > 0);
        check('E_' + key.replace(/([A-Z])/, '_$1').toUpperCase(), nonInt);
        check('E_' + key.replace(/([A-Z].+)/, '_Range').toUpperCase(), [
          // Exercise overflow:
          // (size > INT_MAX - offset)
          // (offset > INT_MAX - size)
          maxInt - maxOffset + 1,
          // Exercise range:
          // (offset + size > length)
          maxOffset + maxSize + 1
        ]);
        if (method === 'cipher') {
          if (key === 'keySize') {
            check('E_KEY_INVALID', [0, algorithm.keySize - 1]);
          }
          if (key === 'ivSize') {
            check('E_IV_INVALID', [0, algorithm.ivSize - 1]);
          }
          if (key === 'aadSize') {
            if (algorithm.tagSize === 0) {
              check('E_AAD_INVALID', [2]);
            }
          }
          if (key === 'tagSize') {
            if (algorithm.tagSize) {
              check('E_TAG_INVALID', [0]);
            } else {
              check('E_TAG_INVALID', [1]);
            }
          }
        }
      }
    }
  );

  // Finally, execute these arguments synchronously and assert exceptions:
  map.forEach(
    function(tuple) {
      var params = tuple[0];
      var code = tuple[1];
      assert(binding.hasOwnProperty(code));
      assert(typeof binding[code] === 'string');
      assert(binding[code]);
      try {
        binding[method].apply(binding, params);
      } catch (exception) {
        if (exception.message === binding[code]) {
          console.log(
            'PASS: Exception:', method + '()', 'args=' + params.length,
            code + '=' + JSON.stringify(exception.message)
          );
          return;
        }
        console.log(method, params.length, params);
        throw new Error('unexpected exception: ' + exception.message);
      }
      console.log(method, params.length, params);
      throw new Error('expected ' + code);
    }
  );
}

assert(common.CIPHER_BLOCK_MAX === binding.CIPHER_BLOCK_MAX);


// Test exceptions:
['cipher', 'hash', 'hmac'].forEach(
  function(method) {
    var signatures = common[method].signatures;
    var algorithms = common[method].algorithm;
    // We use for loops to avoid polluting any thrown stack trace:
    for (var si = 0; si < signatures.length; si++) {
      for (var ai = 0; ai < algorithms.length; ai++) {
        Probe(method, signatures[si], algorithms[ai]);
      }
    }
  }
);

console.log('\r\n  SEED=' + common.seed + '\r\n');

// Test execution:
var queue = new Queue(8);
queue.onData = function(test, end) {
  var a = common[test.method].parameters();
  var b = Copy(a);
  var bad = 0;
  function run() {
    Inspect(test, a);
    Execute(test, a, binding,
      function(...x) {
        Execute(test, b, common.independent,
          function(...y) {
            Compare(test, x, y, 'result');
            Compare(test, a, b, 'arguments');
            if (test.method != 'cipher') return end();
            // Test cipher roundtrip by decrypting ciphertext:
            if (a[1] === 0) {
              if (bad) {
                // We must assert that an error is raised. We do not rely on the
                // independent implementation (by using Compare) since it also
                // uses OpenSSL.
                // This is how we found:
                // https://github.com/openssl/openssl/issues/8345
                assert(y[0] instanceof Error);
                assert(x[0] instanceof Error);
                assert(x[0].message === y[0].message);
                assert(x[0].message === binding.E_CORRUPT);
              }
              return end();
            }
            a[1] = 0;
            b[1] = 0;
            if (a.length <= 8) {
              assert(Buffer.isBuffer(x[1]));
              // Set source = target:
              a[4] = x[1];
              b[4] = y[1];
            } else {
              assert(Number.isInteger(x[1]));
              // Set source = target:
              a[8] = a[11];
              b[8] = b[11];
              // Set sourceOffset = targetOffset:
              a[9] = a[12];
              b[9] = b[12];
              // Set sourceSize = targetSize:
              a[10] = x[1];
              b[10] = y[1];
              // Set target = (targetOffset + targetSize):
              a[11] = Buffer.alloc(a[12] + x[1] + common.CIPHER_BLOCK_MAX, 255);
              b[11] = Buffer.alloc(b[12] + y[1] + common.CIPHER_BLOCK_MAX, 255);
            }
            // Test that AEAD cipher detects corruption:
            if ((a.length === 7 || a.length === 8) && a[6].length > 0) {
              if (common.random() < 0.1) bad |= Bad(a[2], b[2]); // key
              if (common.random() < 0.1) bad |= Bad(a[3], b[3]); // iv
              if (common.random() < 0.1) bad |= Bad(a[4], b[4]); // source
              if (common.random() < 0.1) bad |= Bad(a[5], b[5]); // aad
              if (common.random() < 0.1) bad |= Bad(a[6], b[6]); // tag
            } else if ((a.length === 19 || a.length === 20) && a[18] > 0) {
              if (common.random() < 0.1) bad |= Bad(a[2], b[2], b[3], b[4]);
              if (common.random() < 0.1) bad |= Bad(a[5], b[5], b[6], b[7]);
              if (common.random() < 0.1) bad |= Bad(a[8], b[8], b[9], b[10]);
              if (common.random() < 0.1) bad |= Bad(a[13], b[13], b[14], b[15]);
              if (common.random() < 0.1) bad |= Bad(a[16], b[16], b[17], b[18]);
              if (bad) {
                // Mark the target buffers as different for Compare():
                // For AEAD cipher zero-copy interface, target buffers will be
                // different if anything else is corrupt. This is because the
                // independent implementation throws once final() is called,
                // before copying to the target. This is not the case for AEAD
                // cipher non-zero-copy interface, as both the independent
                // implementation and index.js throw before returning target.
                a[11].different = true;
                b[11].different = true;
              }
            }
            run();
          }
        );
      }
    );
  }
  run();
};
queue.onEnd = function(error) {
  if (error) throw error;
  console.log(new Array(16 + 1).join('='));
  console.log('PASSED ALL TESTS');
  console.log(new Array(16 + 1).join('='));
};
var tests = [];
var methods = ['cipher', 'hash', 'hmac'];
for (var index = 0; index < 8000; index++) {
  tests.push({
    number: index + 1,
    method: methods[Math.floor(common.random() * methods.length)],
    sync: common.random() < 0.5
  });
}
queue.concat(tests);
queue.end();
