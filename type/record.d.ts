import { ContentType, Version } from "@tls/enum";

/**
 * Represents a TLS plaintext record as a specialized `Uint8Array`.
 */
export class TLSPlaintext extends Uint8Array {
  /**
   * Parses a given array into a `TLSPlaintext` instance.
   *
   * @param {Uint8Array} array - The input byte array.
   * @returns {TLSPlaintext} A new `TLSPlaintext` instance created from the array.
   */
  static from(array: Uint8Array): TLSPlaintext;

  /**
   * Creates a `TLSPlaintext` instance from specific type, version, and fragment.
   *
   * @param {ContentType} type - The content type of the plaintext.
   * @param {Version} version - The protocol version.
   * @param {Uint8Array} fragment - The fragment data.
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
   * @param {ContentType} type - The content type.
   * @param {Version} version - The protocol version.
   * @param {Uint8Array} fragment - The fragment data.
   */
  constructor(type: ContentType, version: Version, fragment: Uint8Array);

  /**
   * The content type of the TLS plaintext record.
   * @type {ContentType}
   */
  readonly type: ContentType;

  /**
   * The protocol version of the TLS plaintext record.
   * @type {Version}
   */
  readonly version: Version;

  /**
   * The fragment data of the TLS plaintext record.
   * @type {Uint8Array}
   */
  readonly fragment: Uint8Array;

  /**
   * The underlying `Struct` instance representing the TLS plaintext record.
   * @type {[Uint8Array,Uint8Array,Uint8Array]}
   */
  readonly items: [Uint8Array, Uint8Array, Uint8Array];
}
