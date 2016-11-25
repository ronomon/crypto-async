var ram = 268435456;
var cpus = require('os').cpus();
var cpu = cpus[0].model;
var cores = cpus.length;
// Using more cores increases throughput.
// Using more than 1/2 available cores can increase latency.
var concurrency = Math.max(2, Math.round(cores / 2));
process['UV_THREADPOOL_SIZE'] = cores;

var common = require('./common.js');
var binding = {
  'crypto': common.independent,
  'crypto-async': require('.')
};
var Queue = require('ronomon-queue');

var Algorithms = {};

Algorithms.Cipher = [
  { name: 'AES-256-CTR', keySize: 32, ivSize: 16 }
];

Algorithms.Hash = Algorithms.HMAC = [
  { name: 'SHA256', targetSize: 32 }
];

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
    end
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

function benchmark(type, vectors, name, binding, end) {
  if (name == 'crypto-async') {
    var queueConcurrency = concurrency;
  } else {
    var queueConcurrency = 1;
  }
  var now = Date.now();
  var sum = 0;
  var time = 0;
  var count = 0;
  var queue = new Queue(queueConcurrency);
  queue.onData = function(vector, end) {
    var hrtime = process.hrtime();
    Execute[type](binding, vector,
      function(error) {
        if (error) return end(error);
        var difference = process.hrtime(hrtime);
        var ns = (difference[0] * 1e9) + difference[1];
        sum += vector.sourceSize;
        time += ns;
        count++;
        end();
      }
    );
  };
  queue.onEnd = function(error) {
    if (error) return end(error);
    var elapsed = Date.now() - now;
    var latency = (time / count) / 1000000;
    var throughput = sum / elapsed / 1000;
    display([
      name + ':',
      'Latency:',
      latency.toFixed(3) + 'ms',
      'Throughput:',
      throughput.toFixed(2) + ' MB/s'
    ]);
    // Rest between benchmarks to leave room for GC:
    setTimeout(end, 100);
  };
  queue.push(vectors);
  queue.end();
}

function display(columns) {
  var string = columns[0];
  while (string.length < 15) string = ' ' + string;
  string += ' ' + columns.slice(1).join(' ');
  console.log(string);
}

console.log('');
display([ 'CPU:', cpu ]);
display([ 'Cores:', cores ]);
display([ 'Threads:', concurrency ]);

var queue = new Queue();
queue.onData = function(type, end) {
  console.log('');
  console.log('============================================================');
  var queue = new Queue();
  queue.onData = function(sourceSize, end) {
    var vectors = [];
    var length = Math.min(10000, Math.round(ram / 4 / sourceSize));
    console.log('');
    if (type === 'Cipher') {
      var algorithm = Algorithms[type][0].name;
    } else {
      var algorithm = type.toUpperCase() + '-' + Algorithms[type][0].name;
    }
    display([
      algorithm + ':',
      length + ' x ' + sourceSize + ' Bytes'
    ]);
    while (length--) {
      vectors.push(new common.Vector[type](
        Algorithms[type],
        undefined,
        sourceSize
      ));
    }
    var queue = new Queue();
    queue.onData = function(name, end) {
      benchmark(type, vectors, name, binding[name], end);
    };
    queue.onEnd = end;
    queue.push([
      'crypto',
      'crypto-async'
    ]);
    queue.end();
  };
  queue.onEnd = end;
  queue.push([
    256,
    1024,
    4096,
    65536,
    1048576
  ]);
  queue.end();
};
queue.onEnd = function(error) {
  if (error) throw error;
  console.log('');
};
queue.push([
  'Cipher',
  'Hash',
  'HMAC'
]);
queue.end();
