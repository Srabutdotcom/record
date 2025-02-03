/**
 * Represents a TLSCiphertext structure in a TLS handshake.
 * Data format to be supplied for encryption process.
 */
export declare class TLSCiphertext extends Uint8Array {
  /**
   * Constructs a new `TLSCiphertext` instance from an existing array.
   *
   * @param array - The array containing the ciphertext data.
   * @returns A new instance of `TLSCiphertext`.
   */
  static from(array: Uint8Array | number[]): TLSCiphertext;

  /**
   * Constructs a `TLSCiphertext` instance.
   *
   * @param encrypted_record - The encrypted record data.
   */
  constructor(encrypted_record: Uint8Array);

  /**
   * The header portion of the TLSCiphertext.
   */
  header: Uint8Array;

  /**
   * The encrypted record data within the TLSCiphertext.
   */
  encrypted_record: Uint8Array;
}
