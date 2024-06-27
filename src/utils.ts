import { Field, UInt32, Bytes } from 'o1js';
import { bytesToWord, chunk } from './sha256/utils.js';

export { wordAtIndex, toMessageBlocks };

//TODO Add JSDoc
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

  //TODO Add error message
  totalIndex.assertEquals(1);

  return UInt32.Unsafe.fromField(totalValues);
}

//TODO Refine notation and add JSDoc
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


