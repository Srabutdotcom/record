//@ts-self-types = "../type/record.d.ts"
import { Struct, Uint16 } from "./dep.ts";
import { Version, ContentType } from "./dep.ts"

export class TLSPlaintext extends Uint8Array {
   static from(array){
      let offset = 0;
      const copy = Uint8Array.from(array);
      const type = ContentType.from(copy);offset+=1;
      const version = Version.from(copy.subarray(offset));offset+=2;
      const lengthOf = Uint16.from(copy.subarray(offset)).value; offset+=2;
      const fragment = copy.subarray(offset, offset+lengthOf)
      return new TLSPlaintext(type, version, fragment)
   }
   static createFrom(type, version, fragment){ return new TLSPlaintext(type, version, fragment)}
   constructor(type, version, fragment){
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
   }
}