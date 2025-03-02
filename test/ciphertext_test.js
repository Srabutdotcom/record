import { TLSCiphertext } from "../src/ciphertext.js";

const encrypted_record = Uint8Array.of(254,210,42,83,193,90,33,198,68,235,159,161,30,146,52,57,149,30,148,171,56,71,64,10,195,235,40,137,67,198,93,35,172,181,232,125,206,136,146,228,136,13,194,187,140,159,204,22,21,84,47,161,176,182,205,97,81,181);

const ciphertext = TLSCiphertext.from(encrypted_record);
const header = ciphertext.header;
const content = ciphertext.encrypted_record;
