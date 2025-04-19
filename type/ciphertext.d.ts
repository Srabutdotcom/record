/**
 * Represents a TLSCiphertext structure in a TLS handshake.
 * This structure contains the encrypted data along with its header.
 * It is used in the encryption process within TLS 1.3.
 * @see {@link https://jsr.io/@tls/record jsr.io@tls/record}
 * @version 0.2.6
 */
export declare class TLSCiphertext extends Uint8Array {
  /**
   * Creates an instance of TLSCiphertext from the given arguments.
   * @param {...any[]} args - Arguments used to create the instance.
   * @returns {TLSCiphertext} A new instance of TLSCiphertext.
   */
  static from(...args: any[]): TLSCiphertext;

  /**
   * Constructs a TLSCiphertext instance.
   * If the first argument is a Uint8Array, it applies `sanitize` before initializing.
   * @param {...any[]} args - Arguments to initialize the Uint8Array.
   */
  constructor(...args: any[]);

  /**
   * Retrieves the header (first 5 bytes) of the TLSCiphertext.
   * @returns {Uint8Array} The header bytes.
   */
  get header(): Uint8Array;

  /**
   * Retrieves the encrypted record.
   * @returns {Uint8Array} The encrypted part of the TLSCiphertext.
   */
  get encrypted_record(): Uint8Array;
}
