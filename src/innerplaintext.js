//@ts-self-types="../type/innerplaintext.d.ts"
import { ContentType } from "./dep.ts";

/**
 * Is the output from decrypt process of TLSChipertext
 */
export class TLSInnerPlaintext extends Uint8Array {
   content;
   type;
   numZeros;
   static from(array) {
      const copy = Uint8Array.from(array);
      const lastNonZeroIndex = copy.reduceRight((li, v, i) => (li === -1 && v !== 0 ? i : li), -1);
      const content = copy.slice(0, lastNonZeroIndex);
      const type = ContentType.fromValue(copy[lastNonZeroIndex]);
      const numZeros = copy.length - 1 - lastNonZeroIndex;
      return new TLSInnerPlaintext(content, type, numZeros)
   }
   constructor(content, type, numZeros = 0) {
      const struct = new Uint8Array(content.length + 1 + numZeros);
      struct.set(content, 0);
      struct[content.length] = +type;
      super(struct);
      this.content = content;
      this.type = type;
      this.numZeros = numZeros
   }
   header(keyLength) {
      const lengthOf = this.length + keyLength;
      return Uint8Array.of(+this.type, 3, 3, Math.trunc(lengthOf / 256), lengthOf % 256)
   }
}