//@ts-self-types = "../type/records.d.ts"
import { TLSPlaintext } from "./mod.ts";

export function parseRecords(array) {
   const records = new Set
   let offset = 0;
   while (true) {
      const record = TLSPlaintext.from(array.subarray(offset)); offset += record.length
      records.add(record);
      if (offset >= array.length) break;
   }
   return records;
}