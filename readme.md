# TLSPlaintext - TLS Record Implementation Example

This project implements a representation of TLS plaintext records, including parsing and constructing records, as defined in the TLS protocol. The implementation is useful for understanding and working with TLS 1.2/1.3 records in JavaScript or Deno.

## Work Status

### Completed Work

- [x] TLSPlaintext records

### Pending Work

- [ ] TLSInnerPlaintext
- [ ] TLSCiphertext
- [ ] ...

## Example

```javascript
import { TLSPlaintext } from "./TLSPlaintext.js";
import { ContentType, Version } from "./dep.js";

// Example binary data representing a TLS record
const binaryData = new Uint8Array([22, 3, 3, 0, 5, 72, 101, 108, 108, 111]);

// Parsing a TLSPlaintext record
const parsedRecord = TLSPlaintext.from(binaryData);
console.log("Content Type:", parsedRecord.type);
console.log("Version:", parsedRecord.version);
console.log("Fragment:", parsedRecord.fragment);

// Constructing a new TLSPlaintext record
const type = new ContentType(22); // Example ContentType
const version = new Version(3, 3); // TLS 1.2
const fragment = new Uint8Array([72, 101, 108, 108, 111]); // the content

const newRecord = new TLSPlaintext(type, version, fragment);
console.log("Serialized Record:", newRecord.toUint8Array());
```

## References

- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 8448: Example Handshake Traces for TLS 1.3](https://www.rfc-editor.org/rfc/rfc8448)

### Donation

- https://paypal.me/aiconeid

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.