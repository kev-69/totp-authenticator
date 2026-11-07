import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { Base32Error, decode, encode, normalize } from "../src/otp/base32.js";

// Independent copy of the alphabet, so a typo in the implementation can't hide here.
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const bytes = (s: string) => new TextEncoder().encode(s);

// RFC 4648 §10
const RFC_VECTORS: ReadonlyArray<readonly [string, string]> = [
  ["", ""],
  ["f", "MY======"],
  ["fo", "MZXQ===="],
  ["foo", "MZXW6==="],
  ["foob", "MZXW6YQ="],
  ["fooba", "MZXW6YTB"],
  ["foobar", "MZXW6YTBOI======"],
];

describe("RFC 4648 §10 test vectors", () => {
  it.each(RFC_VECTORS)("encode(%j) = %j", (plain, encoded) => {
    expect(encode(bytes(plain))).toBe(encoded);
  });

  it.each(RFC_VECTORS)("decode(encode(%j)) round-trips from %j", (plain, encoded) => {
    expect(decode(encoded)).toEqual(bytes(plain));
  });

  it.each(RFC_VECTORS)("decodes %j without padding", (plain, encoded) => {
    expect(decode(encoded.replace(/=/g, ""))).toEqual(bytes(plain));
  });
});

describe("what authenticator apps send", () => {
  it("is case-insensitive", () => {
    expect(decode("mzxw6ytboi")).toEqual(bytes("foobar"));
  });

  it("encodes without padding when asked (otpauth:// format)", () => {
    expect(encode(bytes("foobar"), { padding: false })).toBe("MZXW6YTBOI");
  });

  it("normalize() strips spaces and dashes from human-typed keys", () => {
    expect(normalize(" mzxw 6ytb-oi\n")).toBe("MZXW6YTBOI");
  });
});

describe("rejects malformed input", () => {
  it.each(["0", "1", "8", "9"])("rejects confusable digit %j", (digit) => {
    expect(() => decode(`MZ${digit}W6YTB`)).toThrow(Base32Error);
  });

  it.each(["MZXW6YT!", "MZXW 6YTB", "MZXW6YTÉ"])("rejects invalid character in %j", (input) => {
    expect(() => decode(input)).toThrow(Base32Error);
  });

  // Unpadded length mod 8 ∈ {1, 3, 6} can't be produced by any byte string.
  it.each(["A", "MZX", "MZXW6Y", "MZXW6YTBO"])("rejects impossible length %j", (input) => {
    expect(() => decode(input)).toThrow(Base32Error);
  });

  // §3.5: "MY" is the canonical encoding of "f"; "MZ" has a non-zero pad bit.
  it("rejects non-canonical trailing bits", () => {
    expect(() => decode("MZ")).toThrow(Base32Error);
  });

  it.each(["MY==MY==", "MY=", "MY=======", "========"])("rejects bad padding %j", (input) => {
    expect(() => decode(input)).toThrow(Base32Error);
  });

  it("never echoes the (secret) input in the error message", () => {
    const secret = "JBSWY3DPEHPK3PX!";
    try {
      decode(secret);
      expect.unreachable("decode should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Base32Error);
      expect((err as Error).message).not.toContain("JBSWY3DP");
      expect((err as Error).message).not.toContain("!");
    }
  });
});

describe("properties", () => {
  const anyBytes = fc.uint8Array({ maxLength: 64 });
  const base32ish = fc.string({ unit: fc.constantFrom(...ALPHABET), maxLength: 24 });

  it("decode(encode(x)) === x, padded and unpadded", () => {
    fc.assert(
      fc.property(anyBytes, fc.boolean(), (data, padding) => {
        expect(decode(encode(data, { padding }))).toEqual(data);
      }),
    );
  });

  it("padded output length is ceil(n / 5) * 8", () => {
    fc.assert(
      fc.property(anyBytes, (data) => {
        expect(encode(data).length).toBe(Math.ceil(data.length / 5) * 8);
      }),
    );
  });

  // The important one: every string decode() accepts must be the *only*
  // encoding of its bytes. Otherwise typos and truncations get through quietly.
  it("decode is canonical: whatever it accepts re-encodes to the same string", () => {
    fc.assert(
      fc.property(base32ish, (text) => {
        let decoded: Uint8Array;
        try {
          decoded = decode(text);
        } catch (err) {
          expect(err).toBeInstanceOf(Base32Error);
          return;
        }
        expect(encode(decoded, { padding: false })).toBe(text);
      }),
    );
  });
});
