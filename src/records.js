//@ts-self-types = "../type/records.d.ts"
import { TLSPlaintext } from "./mod.ts";
import { parseItems, FullHandshake, HandshakeRole, Handshake } from "./dep.ts"

export function parseRecords(array) {
   return parseItems(array, 0, array.length, TLSPlaintext)//new Set
}

export function parseServerHello(array, clientHello, clientPrivateKey) {
   const [serverHelloRecord, _changeCipherSpec, applicationData] = parseRecords(array);
   const fullHS = new FullHandshake(clientHello, serverHelloRecord.fragment, clientPrivateKey, HandshakeRole.CLIENT);
   const decrypted = fullHS.aead_hs_s.open(applicationData.tlsCipherText)

   return parseItems(decrypted.content, 0, decrypted.content.length, Handshake)
}