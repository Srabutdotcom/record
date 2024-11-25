import { Struct, Version, ContentType } from "../src/dep.ts";

/**
 * Represents a TLSPlaintext record.
 * Extends the `Struct` class to model the structure of a TLS plaintext record.
 */
export class TLSPlaintext extends Struct {
  /**
   * Creates a new `TLSPlaintext` instance from a `Uint8Array`.
   * Parses the array into `ContentType`, `Version`, and the `fragment` data.
   * 
   * @param array - A `Uint8Array` containing the serialized TLS plaintext data.
   * @returns A new instance of `TLSPlaintext`.
   */
  static from(array: Uint8Array): TLSPlaintext;

  /**
   * Constructs a `TLSPlaintext` instance.
   * 
   * @param type - The content type of the TLS record (e.g., `ContentType` instance).
   * @param version - The protocol version of the TLS record (e.g., `Version` instance).
   * @param fragment - The actual plaintext data contained in the TLS record.
   */
  constructor(
    type: ContentType,
    version: Version,
    fragment: Uint8Array
  );

  /** The content type of the TLS record. */
  readonly type: ContentType;

  /** The protocol version of the TLS record. */
  readonly version: Version;

  /** The actual plaintext data contained in the TLS record. */
  readonly fragment: Uint8Array;
}
