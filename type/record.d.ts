import { ContentType, Version } from "@tls/enum";
import { TLSInnerPlaintext } from "../src/innerplaintext.js";
import { TLSCiphertext } from "../src/ciphertext.js";

/**
 * Represents a TLS 1.3 plaintext record at the record layer.
 * This class handles the parsing and construction of TLSPlaintext structures.
 */
export class TLSPlaintext extends Uint8Array {
  /**
   * Parses a `TLSPlaintext` message from a raw byte array.
   *
   * @param {Uint8Array} array - The raw TLS record-layer message.
   * @returns {TLSPlaintext} A parsed `TLSPlaintext` instance.
   */
  static from(array: Uint8Array): TLSPlaintext;

  /**
   * Creates a `TLSPlaintext` instance from type, version, and fragment data.
   *
   * @param {ContentType} type - The content type of the TLS message.
   * @param {Version} version - The TLS protocol version.
   * @param {Uint8Array} fragment - The message fragment.
   * @returns {TLSPlaintext} A new `TLSPlaintext` instance.
   */
  static createFrom(
    type: ContentType,
    version: Version,
    fragment: Uint8Array,
  ): TLSPlaintext;

  /**
   * Constructs a new `TLSPlaintext` instance.
   *
   * @param {ContentType} type - The content type of the TLS message.
   * @param {Version} version - The TLS protocol version (default: `Version.legacy`).
   * @param {Uint8Array} fragment - The message fragment.
   */
  constructor(type: ContentType, version: Version, fragment: Uint8Array);

  /** The content type of the TLS record. */
  type: ContentType;

  /** The TLS protocol version. */
  version: Version;

  /** The raw fragment of the TLS message. */
  fragment: Uint8Array;

  /** Internal structure items. */
  items: any[];

  /**
   * Converts the `TLSPlaintext` instance into a `TLSCiphertext` instance.
   * This method handles encryption at the record layer.
   *
   * @returns {TLSCiphertext} The encrypted TLSCiphertext.
   */
  get tlsCipherText(): TLSCiphertext;

  /**
   * Creates a `TLSInnerPlaintext` instance from this `TLSPlaintext`.
   *
   * @param {number} numZeros - Number of padding bytes to include.
   * @returns {TLSInnerPlaintext} A TLSInnerPlaintext instance.
   */
  tlsInnerPlainText(numZeros: number): TLSInnerPlaintext;

  /**
   * Parses the `fragment` field to extract specific TLS message types.
   * This function modifies `fragment` when it contains a `Handshake` message.
   */
  parse(): void;
}
