/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { sha256Pad, generatePartialSHA } from '@zk-email/helpers';
import { Bytes, Field } from 'o1js';

export { dynamicSha256Pad, generatePartialShaInputs };

//TODO Add JSDoc and when the function throws or not
/**
 * Pads a message according to SHA-256 requirements.
 *
 * @param message - The input message as a Uint8Array.
 * @param maxShaBytes - The maximum number of bytes for the SHA-256 padded message.
 * @returns A tuple containing the padded message and the length of the message before padding.
 * @throws Will throw an error if padding does not complete properly or if the final length is incorrect.
 */
function dynamicSha256Pad(
  message: Uint8Array,
  maxShaBytes: number
): [Bytes, Field] {
  // SHA add padding
  const [messagePadded, messagePaddedLen] = sha256Pad(message, maxShaBytes);

  return [Bytes.from(messagePadded), Field((messagePaddedLen - 64) / 8)];
}

function generatePartialShaInputs(
  message: Uint8Array,
  maxPaddedBytes: number,
  shaPrecomputeSelector?: string
) {
  // 65 comes from the 64 at the end and the 1 bit in the start, then 63 comes from the formula to round it up to the nearest 64.
  // see sha256algorithm.com for a more full explanation of padding length
  const messageSHALength = Math.floor((message.length + 63 + 65) / 64) * 64;
  const [messagePadded, messagePaddedLen] = sha256Pad(
    message,
    Math.max(maxPaddedBytes, messageSHALength)
  );

  const { precomputedSha, bodyRemaining, bodyRemainingLength } =
    generatePartialSHA({
      body: messagePadded,
      bodyLength: messagePaddedLen,
      selectorString: shaPrecomputeSelector,
      maxRemainingBodyLength: maxPaddedBytes,
    });

  // console.log('bodyRemaining length: ', bodyRemainingLength);
  // console.log('body block remaining length: ', bodyRemaining.length);
  return {
    precomputedHash: Bytes.from(precomputedSha!.map(Number)),
    messageRemainingBytes: Bytes.from(bodyRemaining),
    messageRemainingLength: Field(bodyRemainingLength / 8 - 8),
  };
}