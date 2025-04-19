//@ts-self-types="../type/innerplaintext.d.ts"
import { ContentType, unity } from "./dep.ts";

/**
 * ```
 * struct {
      opaque content[TLSPlaintext.length];
      ContentType type;
      uint8 zeros[length_of_padding];
   } TLSInnerPlaintext;
   ```
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
      const array = unity(content, type, new Uint8Array(numZeros));
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

