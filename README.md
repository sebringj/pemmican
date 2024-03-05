<h1 style="display:flex;align-items:center;justify-content:center;flex-direction:row"><img src="./pemmican.webp" width="40px" height="40px" /> Pemmican</h1>

## public/private key pair generation, signing, verification, encryption and decryption

Just like its namesake, the legendary survival food, our "pemmican" module delivers the essentials—public/private key generation, PEM conversion, data signing, verification and encryption/decryption—without any of the bloat.

## Getting Started

### Generating a Key Pair
Generate a public/private key pair to start securing your application. There are 2 types of key-pairs. One can be used for signing and another for encrypting and decrypting. The parameters "generateKeyPair" takes is either "signing" or "encryption".
```typescript
import { Pemmican } from 'https://raw.githubusercontent.com/sebringj/pemmican/main/mod.ts';

async function generateKeys() {
  const { publicKeyPem, privateKeyPem } = await Pemmican.generateKeyPair('signing');
  console.log('Public Key:', publicKeyPem);
  console.log('Private Key:', privateKeyPem);
}

generateKeys();
```

### Signing Data
Sign a piece of data using your private key, ensuring that it can be verified by the recipient.
```typescript
import { Pemmican } from 'https://raw.githubusercontent.com/sebringj/pemmican/main/mod.ts';

async function signMessage() {
  const { privateKeyPem } = await Pemmican.generateKeyPair('signing'); // Assume privateKeyPem is obtained
  const data = 'Hello, Pemmican!';
  const { signatureBase64, timeStampISO } = await Pemmican.signData({ data, privateKeyPem });
  console.log('Signature:', signatureBase64);
  console.log('Timestamp:', timeStampISO);
}

signMessage();
```

### Verifying a Signature
To verify a signature, you'll need the public key, the original data that was signed, and the signature you wish to verify. This ensures the integrity and authenticity of the data.
```typescript
import { Pemmican } from 'https://raw.githubusercontent.com/sebringj/pemmican/main/mod.ts';

async function verifySignature() {
  // Obtain initial keys, usually generated beforehand and stored
  const { publicKeyPem, privateKeyPem } = await Pemmican.generateKeyPair('signing');

  // Create test data
  const data = 'Hello, Pemmican!';
  
  // Signing the data to generate a signature
  const { signatureBase64 } = await Pemmican.signData({ data, privateKeyPem });

  // Now, verifying the signature with the public key
  const isValid = await Pemmican.verifySignature({ data, signatureBase64, publicKeyPem });

  if (isValid) {
    console.log('The signature is valid.');
  } else {
    console.log('The signature is invalid.');
  }
}

verifySignature();
```

This example guides you through the process of:

1. Assuming you have a public key (publicKeyPem) and a private key (privateKeyPem).
1. Signing a message with the private key to produce a signature.
1. Verifying the signature using the corresponding public key to ensure the message's integrity and authenticity.

Remember, in a real-world scenario, the public key and the signature would typically be shared with the recipient (for verification), while the private key is securely stored and used for signing by the sender.

### Encrypt and Decrypt using public/private keys
To encrypt a payload and decrypt it, you use the public key to encrypt and then the private key to decrypt.
```typescript
import { Pemmican } from 'https://raw.githubusercontent.com/sebringj/pemmican/main/mod.ts';

async function encryptAndDecrypt() {
  const { publicKeyPem, privateKeyPem } = await Pemmican.generateKeyPair('encryption');
  const data = "Secret message";

  const encryptedData = await Pemmican.encryptWithPublicKey({ data, publicKeyPem });
  const decryptedData = await Pemmican.decryptWithPrivateKey({ encryptedData, privateKeyPem });
  
  if (data === decryptedData) {
    console.log('The decrypted data matches the original data.')
  } else {
    console.log('The decrypted data does not match the original data.')
  }
}

encryptAndDecrypt();
```

In this example, the sender would be given a public key first from the receiver. The sender then can use the public key to encrypt the message and only then the receiver can decrypt it.