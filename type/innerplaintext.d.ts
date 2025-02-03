import { ContentType } from "../src/dep.ts";
/**
 * Represents a TLSInnerPlaintext structure as per the TLS 1.3 specification.
 * as a output of decryption process
 */
export class TLSInnerPlaintext extends Uint8Array {
  /** The content of the plaintext. */
  content: Uint8Array;

  /** The content type associated with this plaintext. */
  type: ContentType;

  /** The number of trailing zero bytes in the structure. */
  numZeros: number;

  /**
   * Parses a `TLSInnerPlaintext` instance from a given array.
   * @param {Uint8Array} array - The input array to parse.
   * @returns {TLSInnerPlaintext} The parsed `TLSInnerPlaintext` instance.
   */
  static from(array: Uint8Array): TLSInnerPlaintext;

  /**
   * Constructs a `TLSInnerPlaintext` instance.
   * @param {Uint8Array} content - The main content of the plaintext.
   * @param {ContentType} type - The content type associated with the plaintext.
   * @param {number} [numZeros=0] - The number of trailing zero bytes (default is 0).
   */
  constructor(content: Uint8Array, type: ContentType, numZeros?: number);

  /**
   * Generates a header for this plaintext structure.
   * @param {number} keyLength - The length of the encryption key.
   * @returns {Uint8Array} The generated header.
   */
  header(keyLength: number): Uint8Array;
}
