import { Field, UInt32, Bytes, assert, Provable, UInt8 } from 'o1js';

export {
  wordAtIndex,
  generateMessageBlocks,
  bytesToWords,
  wordToBytes,
  assertZeroPadding,
};

/**
 * Retrieves the UInt32 word at a specified index from an array of UInt32 words.
 *
 * @param wordsArray - An array of UInt32 words.
 * @param index - The index of the word to retrieve as a Field.
 * @returns The UInt32 word at the specified index.
 * @throws Will throw an error if the index is out of bounds or if multiple indices match.
 */
function wordAtIndex(wordsArray: UInt32[], index: Field): UInt32 {
  const length = wordsArray.length;
  let totalIndex = Field(0);
  let totalValues = Field(0);

  for (let i = 0; i < length; i++) {
    const isIndex = index.equals(i).toField();
    const isValue = isIndex.mul(wordsArray[i].value);

    totalValues = totalValues.add(isValue);
    totalIndex = totalIndex.add(isIndex);
  }

  // Asserting that exactly one index matches
  const errorMessage =
    'Invalid index: Index out of bounds or multiple indices match!';
  totalIndex.assertEquals(1, errorMessage);

  return UInt32.Unsafe.fromField(totalValues);
}

/**
 * Splits a padded message into 512-bit (64-byte) message blocks for SHA-256 processing.
 *
 * @param paddedMessage - The input Bytes object representing the padded message.
 * @returns An array of 512-bit message blocks, each block containing 16 UInt32 words.
 */
function generateMessageBlocks(paddedMessage: Bytes): UInt32[][] {
  // Split the message into 32-bit chunks
  const chunks: UInt32[] = [];

  for (let i = 0; i < paddedMessage.length; i += 4) {
    // Chunk 4 bytes into one UInt32, as expected by SHA-256
    // bytesToWord expects little endian, so we reverse the bytes
    const chunk = UInt32.Unsafe.fromField(
      bytesToWord(paddedMessage.bytes.slice(i, i + 4).reverse())
    );
    chunks.push(chunk);
  }

  // Split message into 16-element sized message blocks
  // SHA-256 expects n-blocks of 512 bits each, 16 * 32 bits = 512 bits
  return chunk(chunks, 16);
}

/**
 * Asserts that the input array is zero-padded from the given startIndex.
 *
 * @param messageBlocks - The 2D array of 16 UInt32 message blocks.
 * @param digestIndex - The index from which the elements should be 0; assumes startIndex - 1 fits in ceil(log2(maxArrayLen)) bits.
 * @throws Will throw an error if the padding is not correct.
 */
function assertZeroPadding(messageBlocks: UInt32[][], digestIndex: Field) {
  // Calculate the start index for padding based on the digest index
  const paddingStartIndex = digestIndex.add(8).mul(2);

  // Flatten the 2D array of message blocks into a 1D array
  const messageWords = messageBlocks.flat();

  for (let i = 0; i < messageWords.length; i++) {
    // Determine if the current index is past the padding start index
    const isPadded = UInt32.from(i).greaterThan(
      UInt32.Unsafe.fromField(paddingStartIndex)
    );

    // Assert that values past the padding start index are zero
    messageWords[i].value
      .mul(isPadded.toField())
      .assertEquals(0, `Padding error at index ${i}: expected zero.`);
  }
}

/**
 * Splits an array into chunks of a specified size.
 *
 * @param array - The array to be split into chunks.
 * @param size - The size of each chunk.
 * @returns A 2D array where each sub-array is a chunk of the specified size.
 * @throws Will throw an error if the length of the array is not a multiple of the chunk size.
 * @notice Copied from https://github.com/o1-labs/o1js/blob/main/src/lib/util/arrays.ts
 */
function chunk<T>(array: T[], size: number): T[][] {
  assert(
    array.length % size === 0,
    `Array length must be a multiple of ${size}`
  );
  return Array.from({ length: array.length / size }, (_, i) =>
    array.slice(size * i, size * (i + 1))
  );
}

/**
 * Converts an array of UInt8 to a Field element, assuming little endian representation by default.
 *
 * @param wordBytes - An array of UInt8 representing the bytes to be converted.
 * @param reverseEndianness - A boolean indicating whether to reverse the endianness. Defaults to false.
 * @returns A Field element representing the combined value of the input bytes.
 * @notice Edited from https://github.com/o1-labs/o1js/blob/main/src/lib/provable/gadgets/bit-slices.ts
 */
function bytesToWord(wordBytes: UInt8[], reverseEndianness = false): Field {
  return wordBytes.reduce((acc, byte, idx) => {
    const shiftBits = reverseEndianness ? 3 - idx : idx;
    const shift = 1n << BigInt(8 * shiftBits);
    return acc.add(byte.value.mul(shift));
  }, Field.from(0));
}

/**
 * Converts a Field element to an array of UInt8 values, assuming little endian representation by default.
 *
 * @param word - The Field element to be converted.
 * @param bytesPerWord - The number of bytes per word. Defaults to 8.
 * @param reverseEndianness - A boolean indicating whether to reverse the endianness. Defaults to false.
 * @returns An array of UInt8 representing the bytes of the input Field element.
 * @notice Edited from https://github.com/o1-labs/o1js/blob/main/src/lib/provable/gadgets/bit-slices.ts
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

  // Verify the decomposition by converting the bytes back to a Field and comparing to the original word
  bytesToWord(bytes, reverseEndianness).assertEquals(word);

  return bytes;
}

/**
 * Converts an array of UInt8 values to an array of UInt32 Field elements, assuming little endian representation.
 *
 * @param bytes - The array of UInt8 values to be converted.
 * @param bytesPerWord - The number of bytes per word. Defaults to 8.
 * @returns An array of UInt32 Field elements representing the input bytes.
 * @notice Edited from https://github.com/o1-labs/o1js/blob/main/src/lib/provable/gadgets/bit-slices.ts
 */
function bytesToWords(bytes: UInt8[], bytesPerWord = 8): UInt32[] {
  return chunk(bytes, bytesPerWord).map((byteChunk) =>
    UInt32.Unsafe.fromField(bytesToWord(byteChunk, true))
  );
}
