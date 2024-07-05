/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { sha256Pad, generatePartialSHA } from '@zk-email/helpers';
import { Bytes, Field } from 'o1js';

export { dynamicSHA256Pad, generatePartialSHA256Inputs };

/**
 * Pads a message according to SHA-256 requirements and fills up to maxShaBytes.
 *
 * This function adds the necessary padding to the input message for SHA-256
 * and ensures the final length is a multiple of 512 bits (64 bytes). It then
 * extends the padded message to a specified maximum length by adding zero bytes.
 *
 * @param message - The input message as a Uint8Array.
 * @param maxPaddedBytes - The maximum number of bytes for the SHA-256 padded message.
 * @notice maxPaddedBytes should be a multiple of 64 as it represents the max number of 512-bit blocks.
 *         It should also be greater than or equal to the number of bytes after SHA-256 padding; otherwise, it will throw an error.
 * @returns A tuple containing the padded message as Bytes and the index of the first hash value of the preimage digest as Field.
 * @throws Will throw an error if padding does not complete properly or if the final length is incorrect.
 */
function dynamicSHA256Pad(
  message: Uint8Array,
  maxPaddedBytes: number
): [Bytes, Field] {
  // Add SHA-256 padding to the message and pad the rest of the blocks with 0 bytes up to maxPaddedBytes
  const [messagePadded, messageLength] = sha256Pad(message, maxPaddedBytes);

  // Calculate the index of the first hash value of the preimage digest
  const outputHashIndex = Field((messageLength - 64) / 8);

  return [Bytes.from(messagePadded), outputHashIndex];
}

/**
 * Generates inputs for partial SHA-256 hash computation.
 *
 * This function pads the input message according to SHA-256 requirements and slices the padded message blocks up to a precompute selector (does nothing if undefined).
 * The first sliced blocks are hashed to generate a precomputedHash. It then pads the remaining message bytes up to maxPaddedBytes.
 *
 * @param message - The input message as a Uint8Array.
 * @param maxPaddedBytes - The maximum number of bytes for the SHA-256 padded remaining message.
 * @param shaPrecomputeSelector - An optional selector string for precomputing the SHA-256 hash.
 * @returns An object containing the precomputed hash as Bytes, the remaining message bytes as Bytes, and the index of the first hash value of the preimage digest as Field.
 * @throws Will throw an error if the padding process fails or if the message length exceeds the maximum padded bytes.
 */
function generatePartialSHA256Inputs(
  message: Uint8Array,
  maxPaddedBytes: number,
  shaPrecomputeSelector?: string
) {
  // Calculate the padded length: the message length plus padding bits rounded up to the nearest multiple of 64 bytes
  const messageSHALength = Math.floor((message.length + 63 + 65) / 64) * 64;

  // Pad the message according to SHA-256 requirements, ensuring the length does not exceed maxPaddedBytes
  const [messagePadded, messagePaddedLen] = sha256Pad(
    message,
    Math.max(maxPaddedBytes, messageSHALength)
  );

  // Generate the precomputed SHA-256 hash, the remaining message bytes, and the length of the remaining message
  const { precomputedSha, bodyRemaining, bodyRemainingLength } =
    generatePartialSHA({
      body: messagePadded,
      bodyLength: messagePaddedLen,
      selectorString: shaPrecomputeSelector,
      maxRemainingBodyLength: maxPaddedBytes,
    });

  return {
    precomputedHash: Bytes.from(precomputedSha!.map(Number)),
    messageRemainingBytes: Bytes.from(bodyRemaining),
    digestIndex: Field(bodyRemainingLength / 8 - 8),
  };
}
