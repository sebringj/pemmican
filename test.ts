import { Pemmican } from './mod.ts';
import {
  assertEquals,
  assertStringIncludes,
} from 'https://deno.land/std/testing/asserts.ts';

Deno.test('Generate Key Pair', async () => {
  const { publicKeyPem, privateKeyPem } = await CryptoUtils.generateKeyPair();
  assertStringIncludes(publicKeyPem, '-----BEGIN PUBLIC KEY-----');
  assertStringIncludes(privateKeyPem, '-----BEGIN PRIVATE KEY-----');
});

Deno.test('Sign Data', async () => {
  const { privateKeyPem } = await CryptoUtils.generateKeyPair();
  const data = 'Hello, World!';
  const { signatureBase64, timeStampISO } = await CryptoUtils.signData({ data, privateKeyPem });
  assertEquals(typeof signatureBase64, 'string');
  assertEquals(typeof timeStampISO, 'string');
});
