import { Pemmican } from "./mod.ts";
import {
  assertEquals,
  assertNotEquals,
} from "https://deno.land/std/testing/asserts.ts";

Deno.test("generateKeyPair generates a valid key pair", async () => {
  const { publicKeyPem, privateKeyPem } = await Pemmican.generateKeyPair('encryption');
  assertNotEquals(publicKeyPem, undefined);
  assertNotEquals(privateKeyPem, undefined);
  assertNotEquals(publicKeyPem, "");
  assertNotEquals(privateKeyPem, "");
});

Deno.test("signData returns a signature and timestamp", async () => {
  const { privateKeyPem } = await Pemmican.generateKeyPair('signing');
  const data = "Hello, Deno!";
  const { signatureBase64, timeStampISO } = await Pemmican.signData({ data, privateKeyPem });
  assertNotEquals(signatureBase64, undefined);
  assertNotEquals(signatureBase64, "");
  assertNotEquals(timeStampISO, undefined);
  assertNotEquals(timeStampISO, "");
});

Deno.test("verifySignature accurately verifies a valid signature", async () => {
  const { publicKeyPem, privateKeyPem } = await Pemmican.generateKeyPair('signing');
  const data = "Hello, Deno!";
  const { signatureBase64 } = await Pemmican.signData({ data, privateKeyPem });
  const isValid = await Pemmican.verifySignature({ data, signatureBase64, publicKeyPem });
  assertEquals(isValid, true);
});

Deno.test("verifySignature rejects an invalid signature", async () => {
  const { publicKeyPem } = await Pemmican.generateKeyPair('signing');
  const data = "Hello, Deno!";
  // Using an obviously invalid signature
  const signatureBase64 = btoa("invalidSignature");
  const isValid = await Pemmican.verifySignature({ data, signatureBase64, publicKeyPem });
  assertEquals(isValid, false);
});

Deno.test("encryptWithPublicKey and decryptWithPrivateKey with generated keys", async () => {
  const { publicKeyPem, privateKeyPem } = await Pemmican.generateKeyPair('encryption');
  const data = "Secret message";

  const encryptedData = await Pemmican.encryptWithPublicKey({ data, publicKeyPem });
  assertNotEquals(encryptedData, undefined);
  assertNotEquals(encryptedData, "");

  const decryptedData = await Pemmican.decryptWithPrivateKey({ encryptedData, privateKeyPem });
  assertEquals(decryptedData, data);
});
