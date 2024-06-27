/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { SHA256 } from './sha256/sha256.js';
import { bytesToWords, wordToBytes } from './sha256/utils.js';
import { Bytes, Field, UInt32 } from 'o1js';
import { selectSubarray, toMessageBlocks, wordAtIndex } from './utils.js';

export { dynamicSHA2562, dynamicSHA256, partialSHA256 };

/**
 * Computes the SHA-256 hash of arbitrary-length inputs padded up to any max length.
 *
 * @param paddedPreimage - The padded preimage as Bytes.
 * @param digestIndex - The index of the first hash value of the preimage digest as Field.
 * @param initialHashValue - The initial hash values for the SHA-256 computation (optional, defaults to SHA256.initialState).
 * @returns The computed SHA-256 hash as Bytes.
 */
function dynamicSHA256(
  paddedPreimage: Bytes,
  digestIndex: Field,
  initialHashValue = SHA256.initialState
): Bytes {
  // Split the padded preimage into 512-bit (64-byte) message blocks
  const messageBlocks = toMessageBlocks(paddedPreimage);

  // Initialize hash values for each message block
  let hashValues: UInt32[][] = Array.from(
    { length: messageBlocks.length + 1 },
    () => []
  );
  hashValues[0] = [...initialHashValue];

  // Compute hash values for each message block
  for (let i = 0; i < messageBlocks.length; i++) {
    const messageSchedule = SHA256.createMessageSchedule(messageBlocks[i]);
    hashValues[i + 1] = [...SHA256.compression(hashValues[i], messageSchedule)];
  }

  // Flatten the hash values for easy access
  let flattenedHashValues = hashValues.flat();

  // Extract the digest words based on the digest index
  let digestWords: UInt32[] = [];
  for (let i = 0; i <= 7; i++) {
    digestWords.push(wordAtIndex(flattenedHashValues, digestIndex.add(i)));
  }

  // Convert the digest words to Bytes and reverse endianness
  const dynamicDigest = Bytes.from(
    digestWords.map((x) => wordToBytes(x.value, 4, true)).flat()
  );

  return dynamicDigest;
}

/**
 * Computes the partial SHA-256 hash using a precomputed hash and the remaining message blocks (as bytes) of the padded preimage.
 *
 * This function is based on dynamicSHA256 but uses a precomputed hash instead of the initial state.
 * It processes the remaining bytes of the preimage from the point where the precomputed hash ends.
 * The remaining padded preimage bytes are arbitrary-length input that are also padded to a maximum number of bytes.
 *
 * @param precomputedHash - The precomputed hash as Bytes.
 * @param remainingMessageBlocks - The remaining padded message blocks as Bytes.
 * @param digestIndex - The index of the first hash value of the preimage digest as Field.
 * @returns The computed SHA-256 hash as Bytes.
 */
function partialSHA256(
  precomputedHash: Bytes,
  remainingMessageBlocks: Bytes,
  digestIndex: Field
): Bytes {
  // Convert the precomputed hash from Bytes to an array of 32-bit words
  const precomputedHashWords = bytesToWords(precomputedHash.bytes, 4);

  // Compute the dynamic SHA-256 hash using the remaining padded preimage and the precomputed hash words
  const digest = dynamicSHA256(
    remainingMessageBlocks,
    digestIndex,
    precomputedHashWords
  );

  return digest;
}

// uses 'selectSubarray' function
function dynamicSHA2562(
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

//TODO Benchmark the one using select subarray and the one that isn't
//TODO Integrate assert Zero padding inside the dynamic hashing and other checks