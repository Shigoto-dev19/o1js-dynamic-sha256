/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { Bytes, Field, Gadgets } from 'o1js';
import { dynamicSHA256, partialSHA256 } from './dynamic-sha256.js';
import { dynamicSHA256Pad, generatePartialSHA256Inputs } from './helpers.js';
import { generateEmailVerifierInputs } from '@zk-email/helpers';
import {
  verifyDKIMSignature,
  DKIMVerificationResult,
} from '@zk-email/helpers/dist/dkim/index.js';
import fs from 'fs';
import { randomBytes } from 'crypto';

/**
 * Generates a random string at a given max length.
 */
function generateRandomString(
  maxLength: number,
  characterSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
): string {
  const randomLength = Math.floor(Math.random() * maxLength);
  let result = '';
  const charactersLength = characterSet.length;

  for (let i = 0; i < randomLength; i++) {
    const randomIndex = Math.floor(Math.random() * charactersLength);
    result += characterSet.charAt(randomIndex);
  }

  return result;
}

describe('Testing Dynamic SHA-256', () => {
  /**
   * Tests the dynamic SHA-256 hashing function with optional padding size and preimage bytes.
   *
   * @param paddingSize - The desired padding size in bytes. Defaults to the SHA-256 block size.
   * @param preimageBytes - The preimage bytes to hash. If not provided, random bytes will be generated.
   * @param max - The maximum size for randomly generated input bytes.
   * @param hashValueIndex - An optional index to be used in the hash computation.
   */
  function testDynamicSHA256(
    paddingSize?: number,
    preimageBytes?: Uint8Array,
    max = 1000,
    falseDigestIndex = false
  ) {
    // Generate random bytes if preimageBytes is not provided
    const randomSize = Math.floor(Math.random() * max);
    const inputBytes = preimageBytes ?? randomBytes(randomSize);

    /**
     * Calculates the padded length of the input bytes according to SHA-256 padding rules.
     *
     * @param inputLength - The length of the input bytes.
     * @returns The padded length in bytes.
     */
    const getPaddedLength = (inputLength: number) => {
      const inputBits = inputLength * 8;
      const paddingBits = (448 - ((inputBits + 1) % 512) + 512) % 512;
      return (inputBits + 1 + paddingBits + 64) / 8;
    };

    // The number of 512-bit blocks after SHA-256 padding
    const blockSize = getPaddedLength(inputBytes.length);

    // Generate inputs for dynamic SHA-256
    const [paddedPreimage, preimageLength] = dynamicSHA256Pad(
      inputBytes,
      paddingSize ?? blockSize
    );

    // Assert that padded preimage has the expected length as the set max size
    if (paddingSize) {
      expect(paddingSize).toEqual(paddedPreimage.length);
    }

    // Set the digest index
    let digestIndex = preimageLength;
    if (falseDigestIndex) {
      digestIndex = Field.random();
    }

    // Compute the dynamic SHA-256 digest
    const dynamicDigest = dynamicSHA256(paddedPreimage, digestIndex).toHex();

    // Compute the standard SHA-256 digest
    const digest = Gadgets.SHA256.hash(inputBytes).toHex();

    // Assert that the dynamically computed digest is the same as the standard SHA-256 digest
    expect(dynamicDigest).toEqual(digest);
  }

  it('should hash the same preimage without extra padding', () => {
    // Test dynamic SHA-256 with default parameters
    testDynamicSHA256();
  });

  it('should hash the same preimage without extra padding (10 iterations)', () => {
    for (let i = 0; i < 10; i++) {
      testDynamicSHA256();
    }
  });

  it('should produce consistent hash results when padding to 1024 bytes', () => {
    // Test dynamic SHA-256 with padding size set to 1024 bytes
    testDynamicSHA256(1024);
  });

  it('should produce consistent hash results when padding to 1024 bytes (10 iterations)', () => {
    for (let i = 0; i < 10; i++) {
      testDynamicSHA256(1024);
    }
  });

  it('should produce consistent hash results when padding to 1536 bytes', () => {
    testDynamicSHA256(1536);
  });

  it('should produce consistent hash results when padding to 1536 bytes (10 iterations)', () => {
    for (let i = 0; i < 10; i++) {
      testDynamicSHA256(1536);
    }
  });

  it('should produce consistent hash results when padding to 2048 bytes', () => {
    testDynamicSHA256(2048);
  });

  it('should produce consistent hash results when padding to 2048 bytes (10 iterations)', () => {
    for (let i = 0; i < 10; i++) {
      testDynamicSHA256(2048);
    }
  });

  it('should produce consistent hash results when hashing an empty preimage', () => {
    // Test dynamic SHA-256 with empty preimage and padding sizes of 1024 and 2048 bytes
    testDynamicSHA256(1024, Bytes.fromString('').toBytes());
    testDynamicSHA256(2048, Bytes.fromString('').toBytes(), 3000);
  });

  it('should throw when max padding size is less than actual padding', () => {
    // Expect an error when the max padding size is insufficient
    expect(() => testDynamicSHA256(64, undefined, 100000)).toThrow();
  });

  it('should throw when max padding size is not a multiple of 64', () => {
    // Expect an error when the max padding size is not a multiple of 64
    expect(() => testDynamicSHA256(134, undefined, 100)).toThrow();
  });

  it('should throw when generating an incorrect digest index', () => {
    // Expect an error when given an incorrect hash value index
    expect(() => testDynamicSHA256(1024, undefined, 10000, true)).toThrow();
  });

  it('should throw when the padded input length is not a multiple of 64 bytes', () => {
    const inputBytes = Bytes(128).random().toBytes();
    const [paddedPreimage, digestIndex] = dynamicSHA256Pad(inputBytes, 1024);

    // Create false padding by adding 11 random bytes to the padded preimage
    const falsePadding = Bytes.from([
      ...paddedPreimage.bytes,
      ...Bytes(11).random().bytes,
    ]);

    const errorMessage = 'Array length must be a multiple of 16';

    // Assert that an error is thrown when the padded input length is not a multiple of 64 bytes (16 32-bit words)
    expect(() => dynamicSHA256(falsePadding, digestIndex)).toThrowError(
      errorMessage
    );
  });

  it('should throw when non-zero padding is present', () => {
    const inputBytes = Bytes(128).random().toBytes();
    const [paddedPreimage, digestIndex] = dynamicSHA256Pad(inputBytes, 1024);

    // Create false padding by adding 64 random bytes to the padded preimage
    const falsePadding = Bytes.from([
      ...paddedPreimage.bytes,
      ...Bytes(64).random().bytes,
    ]);

    const errorMessage = 'Padding error at index 256: expected zero.';

    // Assert that an error is thrown when the padded input contains non-zero padding
    expect(() => dynamicSHA256(falsePadding, digestIndex)).toThrowError(
      errorMessage
    );
  });

  it('should throw given a false digest index', () => {
    const inputBytes = Bytes(128).random().toBytes();
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const [paddedPreimage, _] = dynamicSHA256Pad(inputBytes, 1024);

    const errorMessage = 'Padding error at index 47: expected zero.';

    // Assert that an error is thrown when the padded input contains non-zero padding
    expect(() => dynamicSHA256(paddedPreimage, Field(15))).toThrowError(
      errorMessage
    );
  });
});

describe('Testing Partial SHA-256', () => {
  /**
   * Tests the partial SHA-256 hashing process.
   *
   * @param selector - The selector string to append to the random string.
   * @param precomputedDigest - The precomputed digest to use for the partial hash.
   * @param digestIndex - The index to use for the dynamic hash of the remaining bytes.
   * @param falseSelector - An optional false selector string to use instead of the correct selector.
   */
  function testPartialSHA256(
    selector?: string,
    precomputedDigest?: Bytes,
    digestIndex?: Field,
    falseSelector?: string
  ) {
    // Generate a random string of 250 characters
    let randomString = generateRandomString(250);
    randomString += selector;
    randomString += generateRandomString(500);

    // Convert the random string to bytes
    const preimageBytes = Bytes.fromString(randomString);

    // Generate partial SHA-256 inputs
    const { precomputedHash, messageRemainingBytes, outputHashIndex } =
      generatePartialSHA256Inputs(
        preimageBytes.toBytes(),
        1536,
        falseSelector ?? selector
      );

    // Compute the partial SHA-256 hash
    const computedPartialHash = partialSHA256(
      precomputedDigest ?? precomputedHash,
      messageRemainingBytes,
      digestIndex ?? outputHashIndex
    ).toHex();

    // Compute the full SHA-256 hash for comparison
    const digest = Gadgets.SHA256.hash(preimageBytes).toHex();

    // Assert that the partial hash matches the full hash
    expect(computedPartialHash).toEqual(digest);
  }

  it('should hash the partial preimage correctly without a selector', () => {
    testPartialSHA256();
  });

  it('should hash the partial preimage correctly with the selector "Mina Blockchain"', () => {
    testPartialSHA256('Mina Blockchain');
  });

  it.skip('should hash the partial preimage correctly with random selectors (10 iterations)', () => {
    for (let i = 0; i < 10; i++) {
      const selector = '0x' + generateRandomString(100);
      testPartialSHA256(selector);
    }
  });

  it('should throw an error for a non-existent precompute selector', () => {
    const errorMessage =
      'Provider SHA precompute selector not found in the body';
    expect(() =>
      testPartialSHA256('Hello World!', undefined, undefined, 'Weather')
    ).toThrowError(errorMessage);
  });

  it('should throw an error for an incorrect precomputed SHA value', () => {
    expect(() =>
      testPartialSHA256('Hello World!', Bytes(32).random())
    ).toThrow();
  });

  it('should throw an error for an incorrect digest index', () => {
    expect(() =>
      testPartialSHA256('Zero Knowledge', undefined, Field.random())
    ).toThrow();
  });
});

//TODO Add more test-cases for partial SHA256
describe('Testing Dynamic & Partial SHA-256 on Email Verification', () => {
  let dkimParams: DKIMVerificationResult;
  let emailInputs: Awaited<ReturnType<typeof generateEmailVerifierInputs>>;
  let header: Bytes;
  let headerHash: string;
  let body: Bytes;
  let bodyHash: string;

  // Setup email verification inputs and hashes before running tests
  beforeAll(async () => {
    const emailBuffer = fs.readFileSync('./src/tester.eml');
    dkimParams = await verifyDKIMSignature(emailBuffer);
    emailInputs = await generateEmailVerifierInputs(emailBuffer, {
      shaPrecomputeSelector: 'thousands',
    });
    header = Bytes.from(dkimParams.headers);
    headerHash = Gadgets.SHA256.hash(header).toHex();
    body = Bytes.from(dkimParams.body);
    bodyHash = Buffer.from(dkimParams.bodyHash, 'base64').toString('hex');
  });

  it('should generate the same dynamic hash for headers with 1024 bytes padding (DKIM)', () => {
    const [paddedHeader, headerHashIndex] = dynamicSHA256Pad(
      header.toBytes(),
      1024
    );
    const headerDynamicHash = dynamicSHA256(
      paddedHeader,
      headerHashIndex
    ).toHex();

    expect(headerDynamicHash).toBe(headerHash);
  });

  it('should generate the same dynamic hash for headers (Circuit Inputs)', () => {
    const paddedHeader = Bytes.from(emailInputs.emailHeader.map(Number));
    const headerHashIndex = Field(
      Number(emailInputs.emailHeaderLength) / 8 - 8
    );
    const headerDynamicHash = dynamicSHA256(
      paddedHeader,
      headerHashIndex
    ).toHex();

    expect(headerDynamicHash).toBe(headerHash);
  });

  it('should generate the same partial hash for body with 1536 bytes padding (DKIM:selector=thousands)', () => {
    const { precomputedHash, messageRemainingBytes, outputHashIndex } =
      generatePartialSHA256Inputs(body.toBytes(), 1536, 'thousands');
    const computedPartialBodyHash = partialSHA256(
      precomputedHash,
      messageRemainingBytes,
      outputHashIndex
    ).toHex();

    expect(computedPartialBodyHash).toBe(bodyHash);
  });

  it('should generate the same partial hash for body with 2048 bytes padding (DKIM:selector=Bitcoin)', () => {
    const { precomputedHash, messageRemainingBytes, outputHashIndex } =
      generatePartialSHA256Inputs(body.toBytes(), 2048, 'Bitcoin');
    const computedPartialBodyHash = partialSHA256(
      precomputedHash,
      messageRemainingBytes,
      outputHashIndex
    ).toHex();

    expect(computedPartialBodyHash).toBe(bodyHash);
  });

  it('should generate the same partial hash for body (Circuit Inputs)', () => {
    const precomputedHash = Bytes.from(emailInputs.precomputedSHA!.map(Number));
    const bodyRemainingBytes = Bytes.from(emailInputs.emailBody!.map(Number));
    const bodyHashIndex = Field(Number(emailInputs.emailBodyLength) / 8 - 8);
    const computedPartialBodyHash = partialSHA256(
      precomputedHash,
      bodyRemainingBytes,
      bodyHashIndex
    ).toHex();

    expect(computedPartialBodyHash).toBe(bodyHash);
  });
});
