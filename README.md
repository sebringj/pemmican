<h1 style="display:flex;align-items:center;justify-content:center;flex-direction:row"><img src="./pemmican.webp" width="40px" height="40px" /> Pemmican</h1>

## The Ultimate Crypto Nutrition for Your Deno Apps

Just like its namesake, the legendary survival food, our "pemmican" module is designed to pack a mighty punch of cryptographic power into your Deno projects. With a lean, mean selection of functions, this module is all about delivering the essential nutrients—public/private key generation, PEM conversion, and data signing—without any of the bloat.

## Why Choose Pemmican?

- **Compact:** Just as pemmican condensed vital sustenance into a small package, our module compresses complex crypto functionality into digestible, easy-to-use methods.
- **Efficient:** Every function in "pemmican" is optimized for performance. It's like getting your daily dose of crypto-vitamins in one go—no filler, all killer.
- **Versatile:** Whether you're trailblazing through the wilderness of web development or setting up camp in the back-end, "pemmican" has got your back. It's the all-in-one toolkit for your cryptographic needs.

## Getting Started

### Generating a Key Pair
Generate a public/private key pair to start securing your application.
```typescript
import { Pemmican } from 'https://raw.githubusercontent.com/sebringj/pemmican/main/mod.ts';

async function generateKeys() {
  const { publicKeyPem, privateKeyPem } = await Pemmican.generateKeyPair();
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
  const { privateKeyPem } = await Pemmican.generateKeyPair(); // Assume privateKeyPem is obtained
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
  const { publicKeyPem } = await Pemmican.generateKeyPair(); // Assume publicKeyPem is obtained separately
  const data = 'Hello, Pemmican!';
  const { privateKeyPem } = await Pemmican.generateKeyPair(); // Assume privateKeyPem is available for signing
  
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