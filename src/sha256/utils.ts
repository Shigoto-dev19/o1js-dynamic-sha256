import { Field, UInt8, Provable, assert } from 'o1js';

export { chunk, bitSlice, bytesToWord, wordToBytes, mod, TupleN };

function chunk<T>(array: T[], size: number): T[][] {
  assert(array.length % size === 0, 'invalid input length');
  return Array.from({ length: array.length / size }, (_, i) =>
    array.slice(size * i, size * (i + 1))
  );
}

function bitSlice(x: bigint, start: number, length: number) {
  return (x >> BigInt(start)) & ((1n << BigInt(length)) - 1n);
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

function mod(x: bigint, p: bigint) {
  x = x % p;
  if (x < 0) return x + p;
  return x;
}

/**
 * tuple type that has the length as generic parameter
 */
type TupleN<T, N extends number> = N extends N
  ? number extends N
    ? [...T[]] // N is not typed as a constant => fall back to array
    : [...TupleRec<T, N, []>]
  : never;

type TupleRec<T, N extends number, R extends unknown[]> = R['length'] extends N
  ? R
  : TupleRec<T, N, [T, ...R]>;
