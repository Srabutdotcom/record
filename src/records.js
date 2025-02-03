//@ts-self-types = "../type/records.d.ts"
import { TLSPlaintext } from "./mod.ts";
import { parseItems } from "./dep.ts"

export function parseRecords(array) {
   return parseItems(array, 0, array.length, TLSPlaintext)//new Set
}