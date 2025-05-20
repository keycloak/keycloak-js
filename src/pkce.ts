import { bytesToBase64, sha256Digest } from "./helpers.js";

export const generateCodeVerifier = (len: number): string =>
  Array.from(crypto.getRandomValues(new Uint8Array(len)))
    .map(
      (val) =>
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[
          val % 62
        ],
    )
    .join("");

export const generatePkceChallenge = async (
  pkceMethod: "S256",
  codeVerifier: string,
): Promise<string> => {
  if (pkceMethod !== "S256")
    throw new TypeError(`Invalid value for pkceMethod`);
  const hashBytes = new Uint8Array(await sha256Digest(codeVerifier));
  return bytesToBase64(hashBytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};
