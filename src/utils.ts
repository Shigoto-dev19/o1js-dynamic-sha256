import { Field, UInt32, Bytes, assert } from 'o1js';
import { bytesToWord, chunk } from './sha256/utils.js';

export { wordAtIndex, toMessageBlocks, selectSubarray };

function wordAtIndex(inputArray: UInt32[], index: Field) {
  const length = inputArray.length;
  let totalIndex = Field(0);
  let totalValues = Field(0);

  for (let i = 0; i < length; i++) {
    const isIndex = index.equals(i).toField();
    const isValue = isIndex.mul(inputArray[i].value);

    totalValues = totalValues.add(isValue);
    totalIndex = totalIndex.add(isIndex);
  }

  totalIndex.assertEquals(1);

  return UInt32.Unsafe.fromField(totalValues);
}

function toMessageBlocks(paddedMessage: Bytes) {
  // split the message into 32bit chunks
  let chunks: UInt32[] = [];

  for (let i = 0; i < paddedMessage.length; i += 4) {
    // chunk 4 bytes into one UInt32, as expected by SHA256
    // bytesToWord expects little endian, so we reverse the bytes
    chunks.push(
      UInt32.Unsafe.fromField(
        bytesToWord(paddedMessage.bytes.slice(i, i + 4).reverse())
      )
    );
  }

  // split message into 16 element sized message blocks
  // SHA256 expects n-blocks of 512bit each, 16*32bit = 512bit
  return chunk(chunks, 16);
}

function selectSubarray(
  input: UInt32[],
  startIndex: Field,
  subarrayLength: number
): UInt32[] {
  const maxArrayLen = input.length;
  assert(
    subarrayLength <= maxArrayLen,
    'Subarray length exceeds input array length!'
  );

  // Assert startIndex is not zero
  startIndex.assertNotEquals(
    0,
    'Subarray start index must be greater than zero!'
  );

  const bitLength = Math.ceil(Math.log2(maxArrayLen));
  const shiftBits = startIndex.toBits(bitLength);
  let tmp: Field[][] = Array.from({ length: bitLength }, () =>
    Array.from({ length: maxArrayLen }, () => Field(0))
  );

  for (let j = 0; j < bitLength; j++) {
    for (let i = 0; i < maxArrayLen; i++) {
      let offset = (i + (1 << j)) % maxArrayLen;
      // Shift left by 2^j indices if bit is 1
      if (j === 0) {
        tmp[j][i] = shiftBits[j]
          .toField()
          .mul(input[offset].value.sub(input[i].value))
          .add(input[i].value);
      } else {
        tmp[j][i] = shiftBits[j]
          .toField()
          .mul(tmp[j - 1][offset].sub(tmp[j - 1][i]))
          .add(tmp[j - 1][i]);
      }
    }
  }
  console.log('shifted array length: ', tmp[bitLength - 1].length);

  // Return last row
  let subarray: UInt32[] = [];
  for (let i = 0; i < subarrayLength; i++) {
    const selectedByte = UInt32.Unsafe.fromField(tmp[bitLength - 1][i]);

    // In the context of zk-regex, matched data consists of non-null bytes, while unmatched data consists of null bytes
    // Assert that the subarray data doesn't contain a 0 (null) byte
    selectedByte.value.assertNotEquals(
      0,
      'Selected subarray bytes should not contain null bytes!'
    );

    subarray.push(selectedByte);
  }
  // console.log('\noriginal array length: ', input.length);
  // console.log('subarray out length: ', subarray.length);
  return subarray;
}

export function itemAtIndex(inputArray: Field[], index: Field) {
  const length = inputArray.length;
  let totalIndex = Field(0);
  let totalValues = Field(0);

  for (let i = 0; i < length; i++) {
    const isIndex = index.equals(i).toField();
    const isValue = isIndex.mul(inputArray[i]);

    totalValues = totalValues.add(isValue);
    totalIndex = totalIndex.add(isIndex);
  }

  totalIndex.assertEquals(1);

  return totalValues;
}

export function calculateTotal(inputArray: Field[]) {
  let sum = inputArray[0];
  for (let i = 0; i < inputArray.length; i++) {
    sum = sum.add(inputArray[i]);
  }

  return sum;
}
