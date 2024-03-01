/**
 * A utility class named Pemmican for cryptographic operations, 
 * including converting between PEM format and ArrayBuffer, generating key pairs, and signing data.
 */
export class Pemmican {

  /**
   * Converts an ArrayBuffer to a PEM-formatted string.
   * 
   * @param arrayBuffer The ArrayBuffer to convert.
   * @param type The type of key to generate the PEM for, e.g., "PUBLIC" or "PRIVATE".
   * @returns A string in PEM format.
   */
  static arrayBufferToPem(arrayBuffer: ArrayBuffer, type: string): string {
    const byteArray = new Uint8Array(arrayBuffer);
    const base64 = btoa(String.fromCharCode(...byteArray));
    const pem = `-----BEGIN ${type} KEY-----\n${base64.match(/.{1,64}/g)!.join('\n')}\n-----END ${type} KEY-----\n`;
    return pem;
  }

  /**
   * Converts a PEM-formatted string to an ArrayBuffer.
   * 
   * @param pem The PEM string to convert.
   * @param type The type of key the PEM string represents, e.g., "PUBLIC" or "PRIVATE".
   * @returns An ArrayBuffer representing the binary data of the key.
   */
  static pemToArrayBuffer(pem: string, type: string): ArrayBuffer {
    const base64 = pem.replace(`-----BEGIN ${type} KEY-----`, '').replace(`-----END ${type} KEY-----`, '').replace(/\s/g, '');
    const byteString = atob(base64);
    const byteArray = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; i++) {
        byteArray[i] = byteString.charCodeAt(i);
    }
    return byteArray.buffer;
  }

  /**
   * Asynchronously generates a public/private key pair using RSA and returns them in PEM format.
   * 
   * @returns A Promise that resolves to an object containing the public and private keys in PEM format.
   */
  static async generateKeyPair(): Promise<{ publicKeyPem: string, privateKeyPem: string }> {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
    );

    const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    const publicKeyPem = CryptoUtils.arrayBufferToPem(publicKeyBuffer, 'PUBLIC');
    const privateKeyPem = CryptoUtils.arrayBufferToPem(privateKeyBuffer, 'PRIVATE');

    return { publicKeyPem, privateKeyPem };
  }

  /**
   * Signs data using a private key and returns the signature and a timestamp.
   * 
   * @param params An object containing the data to be signed and the PEM-formatted private key.
   * @returns A Promise that resolves to an object containing the base64 encoded signature and an ISO formatted timestamp.
   */
  static async signData(params: { data: string, privateKeyPem: string }): Promise<{
    signatureBase64: string;
    timeStampISO: string;
  }> {
    const encoder = new TextEncoder();
    const data = encoder.encode(params.data);

    const privateKeyBuffer = CryptoUtils.pemToArrayBuffer(params.privateKeyPem, 'PRIVATE');

    const importedPrivateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyBuffer,
        {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256'
        },
        false,
        ['sign']
    );

    const signatureArrayBuffer = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', importedPrivateKey, data);
    const byteArray = new Uint8Array(signatureArrayBuffer);
    return {
      signatureBase64: btoa(String.fromCharCode(...byteArray)),
      timeStampISO: new Date().toISOString()
    }
  }
}
