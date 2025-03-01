//@ts-self-types = "../type/record.d.ts"
import { Handshake, safeuint8array, Uint16 } from "./dep.ts";
import { Version, ContentType } from "./dep.ts"

/* export class TLSPlaintext extends Uint8Array {
   static from(array) {
      let offset = 0;
      const copy = Uint8Array.from(array);
      const type = ContentType.from(copy); offset += 1;
      const version = Version.from(copy.subarray(offset)); offset += 2;
      const lengthOf = Uint16.from(copy.subarray(offset)).value; offset += 2;
      const fragment = copy.subarray(offset, offset + lengthOf)
      return new TLSPlaintext(type, version, fragment)
   }
   static createFrom(type, version, fragment) { return new TLSPlaintext(type, version, fragment) }
   constructor(type, version = Version.legacy, fragment) {
      const struct = new Struct(
         type.Uint8,
         version.protocolVersion(),
         Uint16.fromValue(fragment.length),
         fragment
      )
      super(struct)

      this.type = type;
      this.version = version;
      this.fragment = fragment
      this.items = struct.items
      //this.parse();
   }

   get tlsCipherText() {
      return TLSCiphertext.from(this);
   }

   tlsInnerPlainText(numZeros) {
      return new TLSInnerPlaintext(this, this.type, numZeros);
   }

   parse() {
      switch (this.type) {
         case ContentType.HANDSHAKE: {
            this.fragment = Handshake.from(this.fragment);
            break;
         }
      }
   }
} */

export class TLSPlaintext extends Uint8Array {
   #type
   #version
   #lengthOf
   #fragment
   static fromAlert(alertMsg){
      return build(ContentType.ALERT, alertMsg)
   }
   static fromApplicationData(applicationData){
      return build(ContentType.APPLICATION_DATA, applicationData)
   }
   static fromChangeCipherSpec(msg){
      return build(ContentType.CHANGE_CIPHER_SPEC, msg)
   }
   static fromHandshake(msg){
      return build(ContentType.Handshake, msg)
   }
   static fromInvalid(msg){
      return build(ContentType.INVALID, msg)
   }
   static from(...args) { return new TLSPlaintext(...args) }
   static create = TLSPlaintext.from
   constructor(...args) {
      args = (args[0] instanceof Uint8Array) ? sanitize(...args) : args
      super(...args)
   }
   get type() {
      this.#type ||= ContentType.from(this.subarray(0))
      return this.#type
   }
   get version() {
      this.#version ||= Version.from(this.subarray(1, 3))
      return this.#version
   }
   get lengthOf() {
      this.#lengthOf ||= Uint16.from(this.subarray(3, 5)).value
      return this.#lengthOf;
   }
   get fragment() {
      if (this.#fragment) return this.#fragment
      switch (this.type) {
         case ContentType.HANDSHAKE: {
            this.#fragment ||= Handshake.from(this.subarray(5, 5 + this.lengthOf))
            break;
         }
         default:
            this.#fragment ||= this.subarray(5, 5 + this.lengthOf)
            break;
      }
      return this.#fragment;
   }
}

function sanitize(...args) {
   const array = args[0];
   try {
      const _isContentType = ContentType.from(array) instanceof ContentType;
      const lengthOf = Uint16.from(array.subarray(3, 5)).value;
      const slicedArray = array.slice(0, 5 + lengthOf);
      return [slicedArray]
   } catch (error) {
      throw error
   }
}

function build(type, msg){
   return TLSPlaintext.from(
      safeuint8array(
         type.byte,
         Version.legacy.byte,
         Uint16.fromValue(msg.length),
         msg
      )
   )
}
