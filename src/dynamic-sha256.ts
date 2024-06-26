/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { SHA256 } from './sha256/sha256.js';
import { bytesToWord, wordToBytes } from './sha256/utils.js';
import { Bytes, Field, UInt32 } from 'o1js';
import { selectSubarray, toMessageBlocks, wordAtIndex } from './utils.js';

export { dynamicSHA256, dynamicSha256, partialSHA256 };

// uses 'selectSubarray' function
function dynamicSHA256(
  paddedPreimage: Bytes,
  preimageBlockLength: Field,
  initialHashValue = SHA256.initialState
) {
  // console.log('headers byte size: ', paddedPreimage.length);

  const messageBlocks = toMessageBlocks(paddedPreimage);
  let hashValues: UInt32[][] = Array.from(
    { length: messageBlocks.length + 1 },
    () => []
  );
  hashValues[0] = [...initialHashValue];

  for (let i = 0; i < messageBlocks.length; i++) {
    const messageSchedule = SHA256.createMessageSchedule(messageBlocks[i]);
    hashValues[i + 1] = [...SHA256.compression(hashValues[i], messageSchedule)];
  }

  const correctBlockIndex = preimageBlockLength.mul(8);
  const blocks = hashValues.flat();
  let exactHashWords = selectSubarray(blocks, correctBlockIndex, 8);
  const dynamicDigest = Bytes.from(
    exactHashWords.map((x) => wordToBytes(x.value, 4).reverse()).flat()
  );

  return dynamicDigest;
}

//TODO Integrate assert Zero padding inside the dynamic hashing
// uses 'wordAtIndex' function
function dynamicSha256(
  paddedPreimage: Bytes,
  preimageBlockLength: Field,
  initialHashValue = SHA256.initialState
) {
  // console.log('headers byte size: ', paddedPreimage.length);

  const messageBlocks = toMessageBlocks(paddedPreimage);
  let hashValues: UInt32[][] = Array.from(
    { length: messageBlocks.length + 1 },
    () => []
  );
  hashValues[0] = [...initialHashValue];

  for (let i = 0; i < messageBlocks.length; i++) {
    const messageSchedule = SHA256.createMessageSchedule(messageBlocks[i]);
    hashValues[i + 1] = [...SHA256.compression(hashValues[i], messageSchedule)];
    // Provable.log(`fH[${i}] `, fH[i], i)
  }

  // const correctBlockIndex = preimageBlockLength.mul(8);
  let exactHashWords: UInt32[] = [];
  let blocks = hashValues.flat();
  // Provable.log('correctBlockIndex: ', correctBlockIndex);
  for (let i = 0; i <= 7; i++) {
    exactHashWords.push(wordAtIndex(blocks, preimageBlockLength.add(i)));
  }

  const dynamicDigest = Bytes.from(
    exactHashWords.map((x) => wordToBytes(x.value, 4).reverse()).flat()
  );

  return dynamicDigest;
}

function partialSHA256(
  precomputedHash: Bytes,
  preimageBlocks: Bytes,
  preimageBlockLength: Field
) {
  let precomputedHashWords: UInt32[] = [];
  for (let i = 0; i < precomputedHash.length; i += 4) {
    // chunk 4 bytes into one UInt32, as expected by SHA256
    // bytesToWord expects little endian, so we reverse the bytes
    precomputedHashWords.push(
      UInt32.Unsafe.fromField(
        bytesToWord(precomputedHash.bytes.slice(i, i + 4), true)
      )
    );
  }

  const digest = dynamicSha256(
    preimageBlocks,
    preimageBlockLength,
    precomputedHashWords
  );

  return digest;
}
