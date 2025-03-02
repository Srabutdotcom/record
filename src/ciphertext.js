import { Uint16 } from "./dep.ts";
/**
 * Represents a TLSCiphertext structure in a TLS handshake.
 * Data format to be supplied for encryption process.
 */
/* export class TLSCiphertext extends Uint8Array {
   static from(array) {
      const copy = Uint8Array.from(array);
      // NOTE should check contentType
      // NOTE legacy version can be bypassed
      const lengthOf = Uint16.from(copy.subarray(3)).value;
      const encrypted_record = copy.subarray(5, lengthOf + 5);
      return new TLSCiphertext(encrypted_record)
   }
   constructor(encrypted_record) {
      const struct = new Uint8Array(encrypted_record.length + 5);
      const lengthOf = Uint16.fromValue(encrypted_record.length);
      struct[0] = 23; // always application data
      struct[1] = 3; // major legacy version;
      struct[2] = 3; // minor legacy verions = TLS v1.2
      struct.set(lengthOf, 3);
      struct.set(encrypted_record, 5);
      super(struct)
      this.header = Uint8Array.from(struct.subarray(0, 5));
      this.encrypted_record = Uint8Array.from(encrypted_record)
   }
} */

/**
 * Represents a TLSCiphertext structure in a TLS handshake.
 * Data format to be supplied for encryption process.
 */
export class TLSCiphertext extends Uint8Array {
   static from(...args){ return new TLSCiphertext(...args)}
   constructor(...args){
      args = (args.length > 1)? args:  (args[0] instanceof Uint8Array) ? sanitize(...args) : (args[0] instanceof ArrayBuffer)? sanitize(...args) : args
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