import { ContentType, Uint16 } from "./dep.ts";
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
      args = (args[0] instanceof Uint8Array) ? sanitize(...args) : args
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
   if(ContentType.fromValue(array.at(0))!==ContentType.APPLICATION_DATA) throw Error(`Expected Application Data - 23`);
   if(array.at(1)!==3)throw Error(`Expected TLS major code - 3`);
   if(array.at(2)!==3)throw Error(`Expected TLS minor code - 3`);
   return args
}