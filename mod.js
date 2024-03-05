"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Pemmican = void 0;
/**
 * A utility class named Pemmican for cryptographic operations,
 * including converting between PEM format and ArrayBuffer, generating key pairs, signing and verifying data.
 */
var Pemmican = /** @class */ (function () {
    function Pemmican() {
    }
    /**
     * Converts an ArrayBuffer to a PEM-formatted string.
     *
     * @param arrayBuffer The ArrayBuffer to convert.
     * @param type The type of key to generate the PEM for, e.g., "PUBLIC" or "PRIVATE".
     * @returns A string in PEM format.
     */
    Pemmican.arrayBufferToPem = function (arrayBuffer, type) {
        var byteArray = new Uint8Array(arrayBuffer);
        var base64 = btoa(String.fromCharCode.apply(String, byteArray));
        var pem = "-----BEGIN ".concat(type, " KEY-----\n").concat(base64.match(/.{1,64}/g).join('\n'), "\n-----END ").concat(type, " KEY-----\n");
        return pem;
    };
    /**
     * Converts a PEM-formatted string to an ArrayBuffer.
     *
     * @param pem The PEM string to convert.
     * @param type The type of key the PEM string represents, e.g., "PUBLIC" or "PRIVATE".
     * @returns An ArrayBuffer representing the binary data of the key.
     */
    Pemmican.pemToArrayBuffer = function (pem, type) {
        var base64 = pem.replace("-----BEGIN ".concat(type, " KEY-----"), '').replace("-----END ".concat(type, " KEY-----"), '').replace(/\s/g, '');
        var byteString = atob(base64);
        var byteArray = new Uint8Array(byteString.length);
        for (var i = 0; i < byteString.length; i++) {
            byteArray[i] = byteString.charCodeAt(i);
        }
        return byteArray.buffer;
    };
    /**
     * Asynchronously generates a public/private key pair for a specified usage (either encryption or signing) and returns them in PEM format.
     *
     * @param usage Specifies the intended use of the key pair: 'encryption' for RSA-OAEP or 'signing' for RSA-PSS.
     * @returns A Promise that resolves to an object containing the public and private keys in PEM format.
     */
    Pemmican.generateKeyPair = function (usage) {
        return __awaiter(this, void 0, void 0, function () {
            var algorithm, keyPair, publicKeyBuffer, privateKeyBuffer, publicKeyPem, privateKeyPem;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (usage === 'encryption') {
                            algorithm = {
                                name: 'RSA-OAEP',
                                modulusLength: 2048,
                                publicExponent: new Uint8Array([1, 0, 1]),
                                hash: 'SHA-256',
                            };
                        }
                        else if (usage === 'signing') {
                            algorithm = {
                                name: 'RSA-PSS',
                                modulusLength: 2048,
                                publicExponent: new Uint8Array([1, 0, 1]),
                                hash: 'SHA-256',
                            };
                        }
                        else {
                            throw new Error("Invalid usage type. Must be 'encryption' or 'signing'.");
                        }
                        return [4 /*yield*/, crypto.subtle.generateKey(algorithm, true, // whether the key is extractable (i.e., can be used in exportKey)
                            usage === 'encryption' ? ['encrypt', 'decrypt'] : ['sign', 'verify'] // Set key usages based on the intended use
                            )];
                    case 1:
                        keyPair = _a.sent();
                        return [4 /*yield*/, crypto.subtle.exportKey('spki', keyPair.publicKey)];
                    case 2:
                        publicKeyBuffer = _a.sent();
                        return [4 /*yield*/, crypto.subtle.exportKey('pkcs8', keyPair.privateKey)];
                    case 3:
                        privateKeyBuffer = _a.sent();
                        publicKeyPem = Pemmican.arrayBufferToPem(publicKeyBuffer, usage === 'encryption' ? 'PUBLIC' : 'PUBLIC');
                        privateKeyPem = Pemmican.arrayBufferToPem(privateKeyBuffer, usage === 'encryption' ? 'PRIVATE' : 'PRIVATE');
                        return [2 /*return*/, { publicKeyPem: publicKeyPem, privateKeyPem: privateKeyPem }];
                }
            });
        });
    };
    /**
     * Signs data using a private key and returns the signature and a timestamp.
     *
     * @param params An object containing the data to be signed and the PEM-formatted private key.
     * @returns A Promise that resolves to an object containing the base64 encoded signature and an ISO formatted timestamp.
     */
    Pemmican.signData = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var encoder, data, privateKeyBuffer, importedPrivateKey, signatureArrayBuffer, byteArray;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        encoder = new TextEncoder();
                        data = encoder.encode(params.data);
                        privateKeyBuffer = this.pemToArrayBuffer(params.privateKeyPem, 'PRIVATE');
                        return [4 /*yield*/, crypto.subtle.importKey('pkcs8', privateKeyBuffer, {
                                name: 'RSA-PSS',
                                hash: 'SHA-256',
                            }, false, // whether the key is extractable (i.e., can be used in exportKey)
                            ['sign'] // specify operations for the key
                            )];
                    case 1:
                        importedPrivateKey = _a.sent();
                        return [4 /*yield*/, crypto.subtle.sign({
                                name: 'RSA-PSS',
                                saltLength: 32,
                            }, importedPrivateKey, data)];
                    case 2:
                        signatureArrayBuffer = _a.sent();
                        byteArray = new Uint8Array(signatureArrayBuffer);
                        return [2 /*return*/, {
                                signatureBase64: btoa(String.fromCharCode.apply(String, byteArray)),
                                timeStampISO: new Date().toISOString()
                            }];
                }
            });
        });
    };
    /**
     * Verifies a signature against the provided data using a public key.
     *
     * @param params An object containing the data, the base64 encoded signature to verify, and the PEM-formatted public key.
     * @returns A Promise that resolves to a boolean indicating whether the signature is valid.
     */
    Pemmican.verifySignature = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var encoder, data, signatureBuffer, publicKeyBuffer, importedPublicKey;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        encoder = new TextEncoder();
                        data = encoder.encode(params.data);
                        signatureBuffer = Uint8Array.from(atob(params.signatureBase64), function (c) { return c.charCodeAt(0); });
                        publicKeyBuffer = Pemmican.pemToArrayBuffer(params.publicKeyPem, 'PUBLIC');
                        return [4 /*yield*/, crypto.subtle.importKey('spki', publicKeyBuffer, {
                                name: 'RSA-PSS',
                                hash: 'SHA-256',
                            }, false, // indicating the key is not extractable
                            ['verify'] // specify the use of the key
                            )];
                    case 1:
                        importedPublicKey = _a.sent();
                        // Use RSA-PSS parameters during verification, including the salt length which must match the one used during signing
                        return [2 /*return*/, crypto.subtle.verify({
                                name: 'RSA-PSS',
                                saltLength: 32, // The salt length should match the one used during the signing process
                            }, importedPublicKey, signatureBuffer, data)];
                }
            });
        });
    };
    /**
     * Encrypts data with the given public key.
     *
     * @param params An object containing the data, the base64 encoded publicKeyPem.
     * @returns A Promise that resolves to a base64 string of encrypted data.
     */
    Pemmican.encryptWithPublicKey = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var encoder, data, publicKeyBuffer, importedPublicKey, encryptedData, byteArray;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        encoder = new TextEncoder();
                        data = encoder.encode(params.data);
                        publicKeyBuffer = Pemmican.pemToArrayBuffer(params.publicKeyPem, 'PUBLIC');
                        return [4 /*yield*/, crypto.subtle.importKey('spki', publicKeyBuffer, {
                                name: 'RSA-OAEP',
                                hash: 'SHA-256'
                            }, false, ['encrypt'])];
                    case 1:
                        importedPublicKey = _a.sent();
                        return [4 /*yield*/, crypto.subtle.encrypt({
                                name: 'RSA-OAEP'
                            }, importedPublicKey, data)];
                    case 2:
                        encryptedData = _a.sent();
                        byteArray = new Uint8Array(encryptedData);
                        return [2 /*return*/, btoa(String.fromCharCode.apply(String, byteArray))];
                }
            });
        });
    };
    /**
     * Decrypts data with the given private key.
     *
     * @param params An object containing the encrypted base64 data, the base64 encoded privateKeyPem.
     * @returns A Promise that resolves to a decrypted string.
     */
    Pemmican.decryptWithPrivateKey = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var encryptedDataBuffer, privateKeyBuffer, importedPrivateKey, decryptedData, decoder;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        encryptedDataBuffer = Uint8Array.from(atob(params.encryptedData), function (c) { return c.charCodeAt(0); });
                        privateKeyBuffer = Pemmican.pemToArrayBuffer(params.privateKeyPem, 'PRIVATE');
                        return [4 /*yield*/, crypto.subtle.importKey('pkcs8', privateKeyBuffer, {
                                name: 'RSA-OAEP',
                                hash: 'SHA-256'
                            }, false, ['decrypt'])];
                    case 1:
                        importedPrivateKey = _a.sent();
                        return [4 /*yield*/, crypto.subtle.decrypt({
                                name: 'RSA-OAEP'
                            }, importedPrivateKey, encryptedDataBuffer)];
                    case 2:
                        decryptedData = _a.sent();
                        decoder = new TextDecoder();
                        return [2 /*return*/, decoder.decode(decryptedData)];
                }
            });
        });
    };
    return Pemmican;
}());
exports.Pemmican = Pemmican;
