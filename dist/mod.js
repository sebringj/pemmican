// deno-fmt-ignore-file
// deno-lint-ignore-file
// This code was bundled using `deno bundle` and it's not recommended to edit it manually

class Pemmican {
    static arrayBufferToPem(arrayBuffer, type) {
        const byteArray = new Uint8Array(arrayBuffer);
        const base64 = btoa(String.fromCharCode(...byteArray));
        const pem = `-----BEGIN ${type} KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END ${type} KEY-----\n`;
        return pem;
    }
    static pemToArrayBuffer(pem, type) {
        const base64 = pem.replace(`-----BEGIN ${type} KEY-----`, '').replace(`-----END ${type} KEY-----`, '').replace(/\s/g, '');
        const byteString = atob(base64);
        const byteArray = new Uint8Array(byteString.length);
        for(let i = 0; i < byteString.length; i++){
            byteArray[i] = byteString.charCodeAt(i);
        }
        return byteArray.buffer;
    }
    static async generateKeyPair(usage) {
        let algorithm;
        if (usage === 'encryption') {
            algorithm = {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([
                    1,
                    0,
                    1
                ]),
                hash: 'SHA-256'
            };
        } else if (usage === 'signing') {
            algorithm = {
                name: 'RSA-PSS',
                modulusLength: 2048,
                publicExponent: new Uint8Array([
                    1,
                    0,
                    1
                ]),
                hash: 'SHA-256'
            };
        } else {
            throw new Error("Invalid usage type. Must be 'encryption' or 'signing'.");
        }
        const keyPair = await crypto.subtle.generateKey(algorithm, true, usage === 'encryption' ? [
            'encrypt',
            'decrypt'
        ] : [
            'sign',
            'verify'
        ]);
        const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const publicKeyPem = Pemmican.arrayBufferToPem(publicKeyBuffer, usage === 'encryption' ? 'PUBLIC' : 'PUBLIC');
        const privateKeyPem = Pemmican.arrayBufferToPem(privateKeyBuffer, usage === 'encryption' ? 'PRIVATE' : 'PRIVATE');
        return {
            publicKeyPem,
            privateKeyPem
        };
    }
    static async signData(params) {
        const encoder = new TextEncoder();
        const data = encoder.encode(params.data);
        const privateKeyBuffer = this.pemToArrayBuffer(params.privateKeyPem, 'PRIVATE');
        const importedPrivateKey = await crypto.subtle.importKey('pkcs8', privateKeyBuffer, {
            name: 'RSA-PSS',
            hash: 'SHA-256'
        }, false, [
            'sign'
        ]);
        const signatureArrayBuffer = await crypto.subtle.sign({
            name: 'RSA-PSS',
            saltLength: 32
        }, importedPrivateKey, data);
        const byteArray = new Uint8Array(signatureArrayBuffer);
        return {
            signatureBase64: btoa(String.fromCharCode(...byteArray)),
            timeStampISO: new Date().toISOString()
        };
    }
    static async verifySignature(params) {
        const encoder = new TextEncoder();
        const data = encoder.encode(params.data);
        const signatureBuffer = Uint8Array.from(atob(params.signatureBase64), (c)=>c.charCodeAt(0));
        const publicKeyBuffer = Pemmican.pemToArrayBuffer(params.publicKeyPem, 'PUBLIC');
        const importedPublicKey = await crypto.subtle.importKey('spki', publicKeyBuffer, {
            name: 'RSA-PSS',
            hash: 'SHA-256'
        }, false, [
            'verify'
        ]);
        return crypto.subtle.verify({
            name: 'RSA-PSS',
            saltLength: 32
        }, importedPublicKey, signatureBuffer, data);
    }
    static async encryptWithPublicKey(params) {
        const encoder = new TextEncoder();
        const data = encoder.encode(params.data);
        const publicKeyBuffer = Pemmican.pemToArrayBuffer(params.publicKeyPem, 'PUBLIC');
        const importedPublicKey = await crypto.subtle.importKey('spki', publicKeyBuffer, {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        }, false, [
            'encrypt'
        ]);
        const encryptedData = await crypto.subtle.encrypt({
            name: 'RSA-OAEP'
        }, importedPublicKey, data);
        const byteArray = new Uint8Array(encryptedData);
        return btoa(String.fromCharCode(...byteArray));
    }
    static async decryptWithPrivateKey(params) {
        const encryptedDataBuffer = Uint8Array.from(atob(params.encryptedData), (c)=>c.charCodeAt(0));
        const privateKeyBuffer = Pemmican.pemToArrayBuffer(params.privateKeyPem, 'PRIVATE');
        const importedPrivateKey = await crypto.subtle.importKey('pkcs8', privateKeyBuffer, {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        }, false, [
            'decrypt'
        ]);
        const decryptedData = await crypto.subtle.decrypt({
            name: 'RSA-OAEP'
        }, importedPrivateKey, encryptedDataBuffer);
        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    }
}
export { Pemmican as Pemmican };
