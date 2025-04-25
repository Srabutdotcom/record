import { ContentType } from "../src/dep.ts";
/**
 * Represents the input for the encryption process in TLS 1.3.
 * 
 * AEAD functions provide a unified encryption and authentication operation
 * that transforms plaintext into authenticated ciphertext and back again.
 * Each encrypted record consists of a plaintext header followed by an
 * encrypted body, which itself contains a type and optional padding.
 * 
 * @see {@link https://www.rfc-editor.org/rfc/rfc8446#section-5.2 RFC 8446 Section 5.2}
 * @see {@link https://jsr.io/@tls/record jsr.io@tls/record}
 * @version 0.2.7
 */
export declare class TLSInnerPlaintext extends Uint8Array {
  /**
   * The TLSPlaintext.fragment value, containing the byte encoding of a handshake
   * or an alert message, or the raw bytes of the application's data to send.
   * 
   * @type {Uint8Array}
   */
  #content: Uint8Array;
  #type: ContentType|number;
  #numZeros: number;
  
  /**
   * Creates an instance of TLSInnerPlaintext from content, type, and padding.
   * 
   * @param {Uint8Array} content - The content of the TLSInnerPlaintext.
   * @param {number} type - The type of the content.
   * @param {number} numZeros - The number of zero-padding bytes.
   * @returns {TLSInnerPlaintext} A new instance of TLSInnerPlaintext.
   */
  static fromContentTypeNumZeros(content: Uint8Array, type: number, numZeros: number): TLSInnerPlaintext;
  
  /**
   * Creates an instance of TLSInnerPlaintext from the given arguments.
   * 
   * @param {...any[]} args - Arguments to initialize the Uint8Array.
   * @returns {TLSInnerPlaintext} A new instance of TLSInnerPlaintext.
   */
  static from(...args: any[]): TLSInnerPlaintext;
  
  /**
   * Constructs a TLSInnerPlaintext instance.
   * If the first argument is a Uint8Array, it applies `sanitize`.
   * 
   * @param {...any[]} args - Arguments to initialize the Uint8Array.
   */
  constructor(...args: any[]);
  
  /**
   * Finds the last non-zero byte index in the Uint8Array.
   * 
   * @returns {number} The last non-zero index in the array.
   */
  get lastNonZeroIndex(): number;
  
  /**
   * Gets the content of the TLSInnerPlaintext, excluding padding.
   * 
   * @returns {Uint8Array} The content without trailing zeros.
   */
  get content(): Uint8Array;
  
  /**
   * Gets the content type of the TLSInnerPlaintext.
   * 
   * @returns {number} The content type.
   */
  get type(): number;
  
  /**
   * Gets the number of zero-padding bytes.
   * 
   * @returns {number} The count of trailing zero bytes.
   */
  get numZeros(): number;
  
  /**
   * Generates a header for the TLSInnerPlaintext based on key length.
   * 
   * @param {number} keyLength - The length of the encryption key.
   * @returns {Uint8Array} The generated header.
   */
  header(keyLength: number): Uint8Array;
}

