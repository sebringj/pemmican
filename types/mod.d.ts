/**
 * A utility class named Pemmican for cryptographic operations,
 * including converting between PEM format and ArrayBuffer, generating key pairs, signing and verifying data.
 */
export declare class Pemmican {
    /**
     * Converts an ArrayBuffer to a PEM-formatted string.
     *
     * @param arrayBuffer The ArrayBuffer to convert.
     * @param type The type of key to generate the PEM for, e.g., "PUBLIC" or "PRIVATE".
     * @returns A string in PEM format.
     */
    private static arrayBufferToPem;
    /**
     * Converts a PEM-formatted string to an ArrayBuffer.
     *
     * @param pem The PEM string to convert.
     * @param type The type of key the PEM string represents, e.g., "PUBLIC" or "PRIVATE".
     * @returns An ArrayBuffer representing the binary data of the key.
     */
    private static pemToArrayBuffer;
    /**
     * Asynchronously generates a public/private key pair for a specified usage (either encryption or signing) and returns them in PEM format.
     *
     * @param usage Specifies the intended use of the key pair: 'encryption' for RSA-OAEP or 'signing' for RSA-PSS.
     * @returns A Promise that resolves to an object containing the public and private keys in PEM format.
     */
    static generateKeyPair(usage: 'encryption' | 'signing'): Promise<{
        publicKeyPem: string;
        privateKeyPem: string;
    }>;
    /**
     * Signs data using a private key and returns the signature and a timestamp.
     *
     * @param params An object containing the data to be signed and the PEM-formatted private key.
     * @returns A Promise that resolves to an object containing the base64 encoded signature and an ISO formatted timestamp.
     */
    static signData(params: {
        data: string;
        privateKeyPem: string;
    }): Promise<{
        signatureBase64: string;
        timeStampISO: string;
    }>;
    /**
     * Verifies a signature against the provided data using a public key.
     *
     * @param params An object containing the data, the base64 encoded signature to verify, and the PEM-formatted public key.
     * @returns A Promise that resolves to a boolean indicating whether the signature is valid.
     */
    static verifySignature(params: {
        data: string;
        signatureBase64: string;
        publicKeyPem: string;
    }): Promise<boolean>;
    /**
     * Encrypts data with the given public key.
     *
     * @param params An object containing the data, the base64 encoded publicKeyPem.
     * @returns A Promise that resolves to a base64 string of encrypted data.
     */
    static encryptWithPublicKey(params: {
        data: string;
        publicKeyPem: string;
    }): Promise<string>;
    /**
     * Decrypts data with the given private key.
     *
     * @param params An object containing the encrypted base64 data, the base64 encoded privateKeyPem.
     * @returns A Promise that resolves to a decrypted string.
     */
    static decryptWithPrivateKey(params: {
        encryptedData: string;
        privateKeyPem: string;
    }): Promise<string>;
}
