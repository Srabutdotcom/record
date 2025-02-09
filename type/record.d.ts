import { ContentType, Handshake, Version } from "../src/dep.ts";

/**
 * Represents a TLSPlaintext structure, extending Uint8Array.
 * This class is used to parse and handle TLS 1.3 plaintext records.
 */
export declare class TLSPlaintext extends Uint8Array {
  #type: ContentType | undefined;
  #version: Version | undefined;
  #lengthOf:number | undefined;
  #fragment: Uint8Array | Handshake | undefined;

  /**
   * Creates an instance of TLSPlaintext from the given arguments.
   * @param {...any[]} args - Arguments to pass to the constructor.
   * @returns {TLSPlaintext} A new instance of TLSPlaintext.
   */
  static from(...args: any[]): TLSPlaintext;

  /**
   * Alias for the `from` method.
   * @param {...any[]} args - Arguments to pass to the constructor.
   * @returns {TLSPlaintext} A new instance of TLSPlaintext.
   */
  static create: (...args: any[]) => TLSPlaintext;

  /**
   * Constructs a TLSPlaintext instance.
   * If the first argument is a Uint8Array, it applies `sanitize`.
   * @param {...any[]} args - Arguments to initialize the Uint8Array.
   */
  constructor(...args: any[]);

  /**
   * Gets the content type of the TLS record.
   * @returns {ContentType} The TLS content type.
   */
  get type(): ContentType;

  /**
   * Gets the version of the TLS record.
   * @returns {Version} The TLS version.
   */
  get version(): Version;

  /**
   * Gets the length of the TLS record fragment.
   * @returns {number} The length of the fragment.
   */
  get lengthOf(): number;

  /**
   * Gets the fragment data of the TLS record.
   * If the type is HANDSHAKE, it returns a `Handshake` instance.
   * Otherwise, it returns a `Uint8Array` containing the fragment data.
   * @returns {Uint8Array | Handshake} The TLS fragment.
   */
  get fragment(): Uint8Array | Handshake;
}
