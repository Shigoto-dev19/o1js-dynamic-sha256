import { Field, Bytes, Gadgets, ZkProgram } from 'o1js';
import { dynamicSHA256, partialSHA256 } from './dynamic-sha256.js';

class Bytes32 extends Bytes(32) {}

class Bytes1024 extends Bytes(1024) {}
class Bytes1536 extends Bytes(1536) {}

const SHA256Program1024 = ZkProgram({
  name: 'sha256',
  publicOutput: Bytes32.provable,
  methods: {
    sha256: {
      privateInputs: [Bytes1024.provable],
      async method(xs: Bytes1024) {
        return Gadgets.SHA256.hash(xs);
      },
    },
  },
});

const SHA256Program1536 = ZkProgram({
  name: 'sha256',
  publicOutput: Bytes32.provable,
  methods: {
    sha256: {
      privateInputs: [Bytes1536.provable],
      async method(xs: Bytes1536) {
        return Gadgets.SHA256.hash(xs);
      },
    },
  },
});

console.log(
  'Standard SHA256 (1024-byte) rows:',
  (await SHA256Program1024.analyzeMethods()).sha256.rows
);

console.log(
  'Standard SHA256 (1536-byte) rows:',
  (await SHA256Program1536.analyzeMethods()).sha256.rows
);

const SHA256Dynamic1024Program = ZkProgram({
  name: 'sha256',
  publicOutput: Bytes32.provable,
  methods: {
    sha256: {
      privateInputs: [Bytes1024.provable, Field],
      async method(preimage: Bytes1024, digestIndex: Field) {
        return dynamicSHA256(preimage, digestIndex);
      },
    },
  },
});

const SHA256Dynamic1536Program = ZkProgram({
  name: 'sha256',
  publicOutput: Bytes32.provable,
  methods: {
    sha256: {
      privateInputs: [Bytes1536.provable, Field],
      async method(preimage: Bytes1536, digestIndex: Field) {
        return dynamicSHA256(preimage, digestIndex);
      },
    },
  },
});

console.log(
  '\nDynamic SHA256 (1024-byte) rows:',
  (await SHA256Dynamic1024Program.analyzeMethods()).sha256.rows
);

console.log(
  'Dynamic SHA256 (1536-byte) rows:',
  (await SHA256Dynamic1536Program.analyzeMethods()).sha256.rows
);

const SHA256Partial1024Program = ZkProgram({
  name: 'sha256',
  publicOutput: Bytes32.provable,
  methods: {
    sha256: {
      privateInputs: [Bytes32.provable, Bytes1024.provable, Field],
      async method(
        precomputedHash: Bytes32,
        preimage: Bytes1024,
        digestIndex: Field
      ) {
        return partialSHA256(precomputedHash, preimage, digestIndex);
      },
    },
  },
});

const SHA256Partial1536Program = ZkProgram({
  name: 'sha256',
  publicOutput: Bytes32.provable,
  methods: {
    sha256: {
      privateInputs: [Bytes32.provable, Bytes1536.provable, Field],
      async method(
        precomputedHash: Bytes32,
        preimage: Bytes1536,
        digestIndex: Field
      ) {
        return partialSHA256(precomputedHash, preimage, digestIndex);
      },
    },
  },
});

console.log(
  '\nPartial SHA256 (1024-byte) rows:',
  (await SHA256Partial1024Program.analyzeMethods()).sha256.rows
);

console.log(
  'Partial SHA256 (1536-byte) rows:',
  (await SHA256Partial1536Program.analyzeMethods()).sha256.rows
);

// bytesToWords --> 32 bytes ==> 81 rows
