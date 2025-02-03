import { TLSPlaintext } from "../src/mod.ts";
import { Handshake } from "../src/dep.ts";
import { ClientHello } from "@tls/keyexchange";

/**
 * Parses an array of bytes into a set of TLSPlaintext records.
 * @param array The Uint8Array containing the raw byte data.
 * @returns A Set containing TLSPlaintext records parsed from the array.
 */
export function parseRecords(array: Uint8Array): Set<TLSPlaintext>;

/**
 * Parses a ServerHello message from a TLS 1.3 handshake response.
 *
 * @param {Uint8Array} array - The raw TLS response containing the ServerHello message.
 * @param {ClientHello} clientHello - The previously sent ClientHello message.
 * @param {Uint8Array} clientPrivateKey - The private key used for key exchange.
 * @returns {Handshake[]} An array of parsed Handshake messages from the decrypted response.
 */
export function parseServerHello(
   array: Uint8Array, 
   clientHello: ClientHello, 
   clientPrivateKey: Uint8Array
): Handshake[];
