//@ts-self-types="../type/innerplaintext.d.ts"
import { ContentType, safeuint8array } from "./dep.ts";

/**
 * Is the input for encryption process in TLS 1.3
 */
/* export class TLSInnerPlaintext extends Uint8Array {
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
} */

/**
 * Is the input for encryption process in TLS 1.3
 * AEAD functions provide a unified encryption
   and authentication operation which turns plaintext into authenticated
   ciphertext and back again.  Each encrypted record consists of a
   plaintext header followed by an encrypted body, which itself contains
   a type and optional padding.
   https://www.rfc-editor.org/rfc/rfc8446#section-5.2
 */
export class TLSInnerPlaintext extends Uint8Array {
   /**
    * content:  The TLSPlaintext.fragment value, containing the byte
      encoding of a handshake or an alert message, or the raw bytes of
      the application's data to send.
    *
    * @type {content}
    */
   #content
   #type
   #numZeros
   static fromContentTypeNumZeros(content, type, numZeros){
      type = (type instanceof ContentType)? type.byte: (typeof type == "number")? Uint8Array.of(type): Uint8Array.of(22) 
      const array = safeuint8array(content, type, new Uint8Array(numZeros));
      return TLSInnerPlaintext.from(array)
   }
   static from(...args){ return new TLSInnerPlaintext(...args)}
   constructor(...args){
      args = (args[0] instanceof Uint8Array) ? sanitize(...args) : args
      super(...args)
   }
   get lastNonZeroIndex(){
      return this.reduceRight((li, v, i) => (li === -1 && v !== 0 ? i : li), -1);
   }
   get content(){
      return this.subarray(0, this.lastNonZeroIndex);
   }
   get type(){
      return ContentType.fromValue(this.at(this.lastNonZeroIndex));
   }
   get numZeros(){
      return this.length - 1 - this.lastNonZeroIndex;
   }
   header(keyLength) {
      const lengthOf = this.length + keyLength;
      return Uint8Array.of(+this.type, 3, 3, Math.trunc(lengthOf / 256), lengthOf % 256)
   }
}

function sanitize(...args){
   const array = args[0];
   const lastNonZeroIndex = array.reduceRight((li, v, i) => (li === -1 && v !== 0 ? i : li), -1);
   try {
      const _type = ContentType.fromValue(array[lastNonZeroIndex]);
      return args
   } catch (error){
      throw error
   }
}

