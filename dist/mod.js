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
    static async generateKeyPair() {
        const keyPair = await crypto.subtle.generateKey({
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([
                1,
                0,
                1
            ]),
            hash: 'SHA-256'
        }, true, [
            'sign',
            'verify'
        ]);
        const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const publicKeyPem = Pemmican.arrayBufferToPem(publicKeyBuffer, 'PUBLIC');
        const privateKeyPem = Pemmican.arrayBufferToPem(privateKeyBuffer, 'PRIVATE');
        return {
            publicKeyPem,
            privateKeyPem
        };
    }
    static async signData(params) {
        const encoder = new TextEncoder();
        const data = encoder.encode(params.data);
        const privateKeyBuffer = Pemmican.pemToArrayBuffer(params.privateKeyPem, 'PRIVATE');
        const importedPrivateKey = await crypto.subtle.importKey('pkcs8', privateKeyBuffer, {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256'
        }, false, [
            'sign'
        ]);
        const signatureArrayBuffer = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', importedPrivateKey, data);
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
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256'
        }, false, [
            'verify'
        ]);
        return crypto.subtle.verify('RSASSA-PKCS1-v1_5', importedPublicKey, signatureBuffer, data);
    }
}
export { Pemmican as Pemmican };
