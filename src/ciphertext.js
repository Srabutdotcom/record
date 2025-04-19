import { Uint16 } from "./dep.ts";

/**
 * ```
 * struct {
      ContentType opaque_type = application_data; - 23 -
      ProtocolVersion legacy_record_version = 0x0303; - TLS v1.2 -
      uint16 length;
      opaque encrypted_record[TLSCiphertext.length];
   } TLSCiphertext;
   ```
 * Represents a TLSCiphertext structure in a TLS handshake.
 * Data format to be supplied for encryption process.
 */
export class TLSCiphertext extends Uint8Array {
   static from(...args){ return new TLSCiphertext(...args)}
   constructor(...args){
      args = (args[0] instanceof Uint8Array)? sanitize(...args) : args
      super(...args)
   }
   get header(){
      return this.subarray(0, 5);
   }
   get encrypted_record(){
      const lengthOf = Uint16.from(this.subarray(3)).value;
      return this.subarray(5, 5 + lengthOf);
   }
}

function sanitize(...args){
   const array = args[0];
   let length, encrypted_record;
   if(array instanceof ArrayBuffer){
      length = Uint16.fromValue(array.byteLength + 5); 
      encrypted_record = new Uint8Array(array);
   } else if(array instanceof Uint8Array){
      length = Uint16.fromValue(array.length + 5); 
      encrypted_record = array;
   } else {
      throw Error(`Expected instanceOf ArrayBuffer or Uint8Array`)
   }
   const result = new Uint8Array(encrypted_record.length + 5);
   result.set([23,3,3],0);
   result.set(length, 3);
   result.set(encrypted_record, 5)
   return [result]
}