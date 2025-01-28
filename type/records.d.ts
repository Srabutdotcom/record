import { TLSPlaintext } from "../src/mod.ts";

/**
 * Parses an array of bytes into a set of TLSPlaintext records.
 * @param array The Uint8Array containing the raw byte data.
 * @returns A Set containing TLSPlaintext records parsed from the array.
 */
export function parseRecords(array: Uint8Array): Set<TLSPlaintext>;