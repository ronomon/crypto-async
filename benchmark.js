process['UV_THREADPOOL_SIZE'] = 64;

var Cores = require('os').cpus().length;
var Concurrency = Math.max(2, Math.round(Cores / 2));

var Common = require('./common.js');

var Binding = {
  'node': Common.independent,
  'sync @ronomon': require('.'),
  'async @ronomon': require('.')
};

var Queue = require('@ronomon/queue');

function Args(method, algorithm, sourceSize) {
  var signatures = Common[method].signatures;
  var signature = signatures[signatures.length - 1];
  var array = [];
  for (var index = 0; index < signature.length; index++) {
    var key = signature[index];
    switch (key) {
    case 'algorithm':
      array.push(algorithm.name);
      break;
    case 'encrypt':
      array.push(1);
      break;
    case 'key':
      if (!Slice(algorithm.keySize || 32, array)) return;
      break;
    case 'iv':
      if (!Slice(algorithm.ivSize, array)) return;
      break;
    case 'source':
      if (!Slice(sourceSize, array)) return;
      break;
    case 'aad':
      if (!Slice(0, array)) return;
      break;
    case 'tag':
      if (!Slice(algorithm.tagSize, array)) return;
      break;
    case 'keyOffset':
    case 'ivOffset':
    case 'sourceOffset':
    case 'targetOffset':
    case 'aadOffset':
    case 'tagOffset':
      array.push(0);
      break;
    case 'keySize':
    case 'ivSize':
    case 'sourceSize':
    case 'aadSize':
    case 'tagSize':
      array.push(array[index - 2].length);
      break;
    case 'target':
      if (method === 'cipher') {
        if (!Slice(sourceSize + 32, array)) return;
      } else {
        if (!Slice(64, array)) return;
      }
      break;
    default:
      throw new Error('unsupported key: ' + key);
    }
  }
  return array;
}

function Bench(binding, method, batch, sourceSize, end) {
  var queue = new Queue(Concurrency);
  var start = process.hrtime();
  var latencies = 0;
  if (binding === 'sync @ronomon') {
    queue.onData = function(args, end) {
      var hrtime = process.hrtime();
      Binding[binding][method].apply(Binding[binding], args);
      var elapsed = process.hrtime(hrtime);
      latencies += (elapsed[0] * 1e9) + elapsed[1];
      end();
    };
  } else {
    queue.onData = function(args, end) {
      var hrtime = process.hrtime();
      Binding[binding][method].call(Binding[binding], ...args,
        function(error) {
          if (error) return end(error);
          var elapsed = process.hrtime(hrtime);
          latencies += (elapsed[0] * 1e9) + elapsed[1];
          end();
        }
      );
    };
  }
  queue.onEnd = function(error) {
    if (error) return end(error);
    var elapsed = process.hrtime(start);
    var seconds = ((elapsed[0] * 1e9) + elapsed[1]) / 1000000 / 1000;
    var latency = latencies / batch.length / 1000000;
    var throughput = batch.length * sourceSize / 1000000 / (seconds || 1);
    Print([
      binding + ':',
      'Latency:',
      latency.toFixed(3) + 'ms',
      'Throughput:',
      throughput.toFixed(2) + ' MB/s'
    ]);
    // Leave room for GC:
    setTimeout(end, 100);
  };
  queue.concat(batch);
  queue.end();
}

function Print(columns) {
  console.log(columns[0].padStart(20, ' ') + ' ' + columns.slice(1).join(' '));
}

var Slab = Buffer.alloc(160 * 1024 * 1024, 255);
var SlabOffset = 0;

function Slice(size, array) {
  if (SlabOffset + size > Slab.length) return false;
  array.push(Slab.slice(SlabOffset, SlabOffset += size));
  return true;
}

console.log('');
Print([ 'CPU:', require('os').cpus()[0].model ]);
Print([ 'Cores:', Cores ]);
Print([ 'Threads:', Concurrency ]);

var queue = new Queue();
queue.onData = function(method, end) {
  var queue = new Queue();
  queue.onData = function(algorithm, end) {
    console.log('');
    console.log(new Array(72 + 1).join('='));
    var queue = new Queue();
    queue.onData = function(sourceSize, end) {
      SlabOffset = 0;
      var batch = [];
      var length = 16384;
      while (length--) {
        var args = Args(method, algorithm, sourceSize);
        if (args) {
          batch.push(args);
        } else {
          break;
        }
      }
      batch = batch.slice(0, Math.pow(2, Math.floor(Math.log2(batch.length))));
      console.log('');
      Print([
        (method === 'hmac' ? 'hmac-' : '') + algorithm.name + ':',
        batch.length + ' x ' + sourceSize + ' Bytes'
      ]);
      var queue = new Queue();
      queue.onData = function(binding, end) {
        Bench(binding, method, batch, sourceSize, end);
      };
      queue.onEnd = end;
      queue.push('node');
      queue.push('sync @ronomon');
      queue.push('async @ronomon');
      queue.end();
    };
    queue.onEnd = end;
    queue.push(256);
    queue.push(1024);
    queue.push(4096);
    queue.push(65536);
    queue.push(1048576);
    queue.end();
  };
  queue.onEnd = end;
  queue.concat(Common[method].algorithm.filter(
    function(algorithm) {
      if (/^(md5|sha1)$/i.test(algorithm.name)) return false;
      if (/-(128|192)-/i.test(algorithm.name)) return false;
      return true;
    }
  ));
  queue.end();
};
queue.onEnd = function(error) {
  if (error) throw error;
  console.log('');
};
queue.push('cipher');
queue.push('hash');
queue.push('hmac');
queue.end();
