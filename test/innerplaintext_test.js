import { Byte } from "../src/dep.ts";
import { TLSInnerPlaintext } from "../src/innerplaintext.js";

const sample = Byte.fromHex(`48 65 6c 6c 6f 20 57 6f 72 6c 64 21 17 00 00 00`);
const tlsInnerPlainText = TLSInnerPlaintext.from(sample);
const back = TLSInnerPlaintext.fromContentTypeNumZeros(tlsInnerPlainText.content, tlsInnerPlainText.type, tlsInnerPlainText.numZeros)
