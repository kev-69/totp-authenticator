/**
 * Base32 (RFC 4648 §6): the format TOTP secrets travel in.
 * Spec notes: docs/spec/01-base32.md
 *
 * The decoder is strict on purpose: anything it accepts must be the one
 * canonical encoding of its bytes. A lax decoder turns typos into different
 * keys, or into an empty key.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** charCode → 5-bit value, or -1. Accepts lowercase too. */
const LOOKUP: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    table[ALPHABET.charCodeAt(i)] = i;
    table[ALPHABET.toLowerCase().charCodeAt(i)] = i;
  }
  return table;
})();

/** Unpadded length mod 8 for each possible leftover byte count (0–4). */
const VALID_REMAINDERS = new Set([0, 2, 4, 5, 7]);

export class Base32Error extends Error {
  override readonly name = "Base32Error";
}

export interface EncodeOptions {
  /** Add `=` to a multiple of 8 chars. Defaults to true (RFC 4648). otpauth:// URIs use false. */
  readonly padding?: boolean;
}

export function encode(data: Uint8Array, options: EncodeOptions = {}): string {
  const padding = options.padding ?? true;
  let buffer = 0; // holds at most 12 bits: up to 4 left over + 8 new
  let bits = 0;
  let out = "";

  for (const byte of data) {
    buffer = ((buffer << 8) | byte) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET.charAt((buffer >>> bits) & 0b11111);
    }
  }
  // Left-align the remaining 1–4 bits and pad with zero bits (RFC 4648 §3.5).
  if (bits > 0) out += ALPHABET.charAt((buffer << (5 - bits)) & 0b11111);

  if (padding) out = out.padEnd(Math.ceil(out.length / 8) * 8, "=");
  return out;
}

export function decode(text: string): Uint8Array {
  const body = stripPadding(text);

  if (!VALID_REMAINDERS.has(body.length % 8)) {
    throw new Base32Error(`invalid length ${body.length}: not a possible Base32 encoding`);
  }

  const out = new Uint8Array(Math.floor((body.length * 5) / 8));
  let buffer = 0; // holds at most 12 bits: up to 7 left over + 5 new
  let bits = 0;
  let index = 0;

  for (let i = 0; i < body.length; i++) {
    const value = LOOKUP[body.charCodeAt(i)]; // out-of-range code → undefined
    if (value === undefined || value < 0) {
      // Report the position only, never the character: this input is a secret.
      throw new Base32Error(`invalid character at position ${i}`);
    }
    buffer = ((buffer << 5) | value) & 0xfff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >>> bits) & 0xff;
    }
  }

  // The 0–4 leftover bits were added by the encoder as zeros (§3.5).
  // If they aren't zero, this isn't the canonical encoding of any byte string.
  if ((buffer & ((1 << bits) - 1)) !== 0) {
    throw new Base32Error("non-canonical encoding: trailing bits are not zero");
  }
  return out;
}

/** Clean a human-typed key ("jbsw y3dp-ehpk") before decoding. Never called implicitly. */
export function normalize(text: string): string {
  return text.replace(/[\s-]/g, "").toUpperCase();
}

/**
 * Padding is optional, but if present it must be the tail of a
 * multiple-of-8 block and must not stand in for a whole block.
 */
function stripPadding(text: string): string {
  const padStart = text.indexOf("=");
  if (padStart === -1) return text;

  const body = text.slice(0, padStart);
  const padLength = text.length - padStart;
  const onlyPadAfter = /^=+$/.test(text.slice(padStart));

  if (!onlyPadAfter) throw new Base32Error("padding may only appear at the end");
  if (text.length % 8 !== 0) throw new Base32Error("padded length must be a multiple of 8");
  if (padLength >= 8 || body.length % 8 === 0) throw new Base32Error("unnecessary padding block");
  return body;
}
