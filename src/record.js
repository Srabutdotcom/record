//@ts-self-types = "../type/record.d.ts"
import { Alert, Handshake, unity, Uint16 } from "./dep.ts";
import { Version, ContentType } from "./dep.ts"

/**
 * ```
 * struct {
      ContentType type;
      ProtocolVersion legacy_record_version;
      uint16 length;
      opaque fragment[TLSPlaintext.length];
   } TLSPlaintext;
   ```
 */
export class TLSPlaintext extends Uint8Array {
   #type
   #version
   #lengthOf
   #fragment
   #groups
   static fromAlert(alertMsg) {
      return build(ContentType.ALERT, alertMsg)
   }
   static fromApplicationData(applicationData) {
      return build(ContentType.APPLICATION_DATA, applicationData)
   }
   static fromChangeCipherSpec(msg) {
      return build(ContentType.CHANGE_CIPHER_SPEC, msg)
   }
   static fromHandshake(msg) {
      return build(ContentType.HANDSHAKE, msg)
   }
   static fromInvalid(msg) {
      return build(ContentType.INVALID, msg)
   }
   static from(...args) { return new TLSPlaintext(...args) }
   static create = TLSPlaintext.from
   constructor(...args) {
      sanitize(args)
      //args = (args[0] instanceof Uint8Array) ? sanitize(...args) : args
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
      const content = this.subarray(5, 5 + this.lengthOf);
      switch (this.type) {
         case ContentType.HANDSHAKE: {
            this.#fragment ||= Handshake.from(content)
            break;
         }
         case ContentType.ALERT: {
            this.#fragment ||= Alert.from(content)
            break;
         }
         default:
            this.#fragment ||= content
            break;
      }
      return this.#fragment;
   }
   set groups(groups) { this.#groups = groups }
   get groups(){ return this.#groups }
}

function sanitize(args) {
   const array = args[0];
   if(!(array instanceof Uint8Array))return;
   try {
      const _isContentType = ContentType.from(array) instanceof ContentType;
      const lengthOf = Uint16.from(array.subarray(3, 5)).value;
      args[0] = array.subarray(0, 5 + lengthOf)
      return
   } catch (error) {
      throw error
   }
}

function build(type, msg) {
   return TLSPlaintext.from(
      unity(
         type.byte,
         Version.legacy.byte,
         Uint16.fromValue(msg.length),
         msg
      )
   )
}
