export class Pemmican {
  // Convert an ArrayBuffer to a PEM string
  static arrayBufferToPem(arrayBuffer: ArrayBuffer, type: string): string {
    const byteArray = new Uint8Array(arrayBuffer);
    const base64 = btoa(String.fromCharCode(...byteArray));
    const pem = `-----BEGIN ${type} KEY-----\n${base64.match(/.{1,64}/g)!.join('\n')}\n-----END ${type} KEY-----\n`;
    return pem;
  }

  // Convert a PEM string to an ArrayBuffer
  static pemToArrayBuffer(pem: string, type: string): ArrayBuffer {
    const base64 = pem.replace(`-----BEGIN ${type} KEY-----`, '').replace(`-----END ${type} KEY-----`, '').replace(/\s/g, '');
    const byteString = atob(base64);
    const byteArray = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; i++) {
        byteArray[i] = byteString.charCodeAt(i);
    }
    return byteArray.buffer;
  }

  // Generate a public/private key pair in PEM format
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

  // Sign data and return signature and timestamp
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
