/**
 * A utility class named Pemmican for cryptographic operations, 
 * including converting between PEM format and ArrayBuffer, generating key pairs, signing and verifying data.
 */
export class Pemmican {

  /**
   * Converts an ArrayBuffer to a PEM-formatted string.
   * 
   * @param arrayBuffer The ArrayBuffer to convert.
   * @param type The type of key to generate the PEM for, e.g., "PUBLIC" or "PRIVATE".
   * @returns A string in PEM format.
   */
  private static arrayBufferToPem(arrayBuffer: ArrayBuffer, type: string): string {
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
  private static pemToArrayBuffer(pem: string, type: string): ArrayBuffer {
    const base64 = pem.replace(`-----BEGIN ${type} KEY-----`, '').replace(`-----END ${type} KEY-----`, '').replace(/\s/g, '');
    const byteString = atob(base64);
    const byteArray = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; i++) {
      byteArray[i] = byteString.charCodeAt(i);
    }
    return byteArray.buffer;
  }

  /**
   * Asynchronously generates a public/private key pair for a specified usage (either encryption or signing) and returns them in PEM format.
   * 
   * @param usage Specifies the intended use of the key pair: 'encryption' for RSA-OAEP or 'signing' for RSA-PSS.
   * @returns A Promise that resolves to an object containing the public and private keys in PEM format.
   */
  public static async generateKeyPair(usage: 'encryption' | 'signing'): Promise<{ publicKeyPem: string, privateKeyPem: string }> {
    let algorithm;
    
    if (usage === 'encryption') {
      algorithm = {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      };
    } else if (usage === 'signing') {
      algorithm = {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      };
    } else {
      throw new Error("Invalid usage type. Must be 'encryption' or 'signing'.");
    }

    const keyPair = await crypto.subtle.generateKey(
      algorithm,
      true, // whether the key is extractable (i.e., can be used in exportKey)
      usage === 'encryption' ? ['encrypt', 'decrypt'] : ['sign', 'verify'] // Set key usages based on the intended use
    );

    const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    const publicKeyPem = Pemmican.arrayBufferToPem(publicKeyBuffer, usage === 'encryption' ? 'PUBLIC' : 'PUBLIC');
    const privateKeyPem = Pemmican.arrayBufferToPem(privateKeyBuffer, usage === 'encryption' ? 'PRIVATE' : 'PRIVATE');

    return { publicKeyPem, privateKeyPem };
  }

  /**
   * Signs data using a private key and returns the signature and a timestamp.
   * 
   * @param params An object containing the data to be signed and the PEM-formatted private key.
   * @returns A Promise that resolves to an object containing the base64 encoded signature and an ISO formatted timestamp.
   */
  public static async signData(params: { data: string, privateKeyPem: string }): Promise<{
    signatureBase64: string;
    timeStampISO: string;
  }> {
    const encoder = new TextEncoder();
    const data = encoder.encode(params.data);

    const privateKeyBuffer = this.pemToArrayBuffer(params.privateKeyPem, 'PRIVATE');

    const importedPrivateKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      },
      false, // whether the key is extractable (i.e., can be used in exportKey)
      ['sign'] // specify operations for the key
    );

    // Specify the salt length for the RSA-PSS signature; it can be equal to hash size (in this case, SHA-256, so 32 bytes)
    const signatureArrayBuffer = await crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 32,
      },
      importedPrivateKey,
      data
    );

    const byteArray = new Uint8Array(signatureArrayBuffer);
    return {
      signatureBase64: btoa(String.fromCharCode(...byteArray)),
      timeStampISO: new Date().toISOString()
    };
  }

  /**
   * Verifies a signature against the provided data using a public key.
   * 
   * @param params An object containing the data, the base64 encoded signature to verify, and the PEM-formatted public key.
   * @returns A Promise that resolves to a boolean indicating whether the signature is valid.
   */
  public static async verifySignature(params: { data: string, signatureBase64: string, publicKeyPem: string }): Promise<boolean> {
    const encoder = new TextEncoder();
    const data = encoder.encode(params.data);
  
    const signatureBuffer = Uint8Array.from(atob(params.signatureBase64), c => c.charCodeAt(0));
  
    const publicKeyBuffer = Pemmican.pemToArrayBuffer(params.publicKeyPem, 'PUBLIC');
  
    // Import the public key using RSA-PSS parameters
    const importedPublicKey = await crypto.subtle.importKey(
      'spki',
      publicKeyBuffer,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      },
      false, // indicating the key is not extractable
      ['verify'] // specify the use of the key
    );
  
    // Use RSA-PSS parameters during verification, including the salt length which must match the one used during signing
    return crypto.subtle.verify(
      {
        name: 'RSA-PSS',
        saltLength: 32, // The salt length should match the one used during the signing process
      },
      importedPublicKey,
      signatureBuffer,
      data
    );
  }

  /**
   * Encrypts data with the given public key.
   * 
   * @param params An object containing the data, the base64 encoded publicKeyPem.
   * @returns A Promise that resolves to a base64 string of encrypted data.
   */
  public static async encryptWithPublicKey(params: { data: string, publicKeyPem: string }): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(params.data);
    const publicKeyBuffer = Pemmican.pemToArrayBuffer(params.publicKeyPem, 'PUBLIC');

    const importedPublicKey = await crypto.subtle.importKey(
      'spki',
      publicKeyBuffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false,
      ['encrypt']
    );

    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP'
      },
      importedPublicKey,
      data
    );

    const byteArray = new Uint8Array(encryptedData);
    return btoa(String.fromCharCode(...byteArray));
  }

  /**
   * Decrypts data with the given private key.
   * 
   * @param params An object containing the encrypted base64 data, the base64 encoded privateKeyPem.
   * @returns A Promise that resolves to a decrypted string.
   */
  public static async decryptWithPrivateKey(params: { encryptedData: string, privateKeyPem: string }): Promise<string> {
    const encryptedDataBuffer = Uint8Array.from(atob(params.encryptedData), c => c.charCodeAt(0));

    const privateKeyBuffer = Pemmican.pemToArrayBuffer(params.privateKeyPem, 'PRIVATE');

    const importedPrivateKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false,
      ['decrypt']
    );

    const decryptedData = await crypto.subtle.decrypt(
      {
        name: 'RSA-OAEP'
      },
      importedPrivateKey,
      encryptedDataBuffer
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedData);
  }
}
