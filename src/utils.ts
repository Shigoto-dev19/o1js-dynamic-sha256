import { Field, UInt32, Bytes, assert, Provable, UInt8 } from 'o1js';

export { wordAtIndex, splitIntoMessageBlocks, bytesToWords, wordToBytes };

/**
 * Retrieves the UInt32 word at a specified index from an array of UInt32 words.
 *
 * @param inputArray - An array of UInt32 words.
 * @param index - The index of the word to retrieve as a Field.
 * @returns The UInt32 word at the specified index.
 * @throws Will throw an error if the index is out of bounds.
 */
function wordAtIndex(inputArray: UInt32[], index: Field): UInt32 {
  const length = inputArray.length;
  let totalIndex = Field(0);
  let totalValues = Field(0);

  for (let i = 0; i < length; i++) {
    const isIndex = index.equals(i).toField();
    const isValue = isIndex.mul(inputArray[i].value);

    totalValues = totalValues.add(isValue);
    totalIndex = totalIndex.add(isIndex);
  }

  // Asserting that exactly one index matches
  totalIndex.assertEquals(
    1,
    'Invalid index: Index out of bounds or multiple indices match!'
  );

  return UInt32.Unsafe.fromField(totalValues);
}

/**
 * Splits a padded message into 512-bit(64-byte) message blocks for SHA-256 processing.
 *
 * @param paddedMessage - The input Bytes object representing the padded message.
 * @returns An array of 512-bit message blocks, each block containing 16 UInt32 words.
 */
function splitIntoMessageBlocks(paddedMessage: Bytes): UInt32[][] {
  // Split the message into 32-bit chunks
  let chunks: UInt32[] = [];

  for (let i = 0; i < paddedMessage.length; i += 4) {
    // Chunk 4 bytes into one UInt32, as expected by SHA-256
    // bytesToWord expects little endian, so we reverse the bytes
    chunks.push(
      UInt32.Unsafe.fromField(
        bytesToWord(paddedMessage.bytes.slice(i, i + 4).reverse())
      )
    );
  }

  // Split message into 16 element sized message blocks
  // SHA-256 expects n-blocks of 512 bits each, 16*32 bits = 512 bits
  return chunk(chunks, 16);
}

function chunk<T>(array: T[], size: number): T[][] {
  assert(array.length % size === 0, 'invalid input length');
  return Array.from({ length: array.length / size }, (_, i) =>
    array.slice(size * i, size * (i + 1))
  );
}

/**
 * Convert an array of UInt8 to a Field element. Expects little endian representation.
 */
function bytesToWord(wordBytes: UInt8[], reverseEndianness = false): Field {
  return wordBytes.reduce((acc, byte, idx) => {
    const shiftBits = reverseEndianness ? 3 - idx : idx;
    const shift = 1n << BigInt(8 * shiftBits);
    return acc.add(byte.value.mul(shift));
  }, Field.from(0));
}

/**
 * Convert a Field element to an array of UInt8. Expects little endian representation.
 * @param bytesPerWord number of bytes per word
 */
function wordToBytes(
  word: Field,
  bytesPerWord = 8,
  reverseEndianness = false
): UInt8[] {
  let bytes = Provable.witness(Provable.Array(UInt8, bytesPerWord), () => {
    let w = word.toBigInt();
    return Array.from({ length: bytesPerWord }, (_, k) => {
      const shiftBits = reverseEndianness ? 3 - k : k;
      return UInt8.from((w >> BigInt(8 * shiftBits)) & 0xffn);
    });
  });

  // check decomposition
  bytesToWord(bytes, reverseEndianness).assertEquals(word);

  return bytes;
}

/**
 * Convert an array of UInt8 to an array of Field elements. Expects little endian representation.
 * @param bytesPerWord number of bytes per word
 */
function bytesToWords(bytes: UInt8[], bytesPerWord = 8): UInt32[] {
  return chunk(bytes, bytesPerWord).map((bytes) =>
    UInt32.Unsafe.fromField(bytesToWord(bytes, true))
  );
}
