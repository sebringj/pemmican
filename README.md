<div style="display:flex;align-items:center;justify-content:center;flex-direction:row">
  <img src="./pemmican.webp" width="40px" height="40px" /> <h1>Pemmican: The Ultimate Crypto Nutrition for Your Deno Apps</h1>
</div>

Just like its namesake, the legendary survival food, our "pemmican" module is designed to pack a mighty punch of cryptographic power into your Deno projects. With a lean, mean selection of functions, this module is all about delivering the essential nutrients—public/private key generation, PEM conversion, and data signing—without any of the bloat.

## Why Choose Pemmican?

- **Compact:** Just as pemmican condensed vital sustenance into a small package, our module compresses complex crypto functionality into digestible, easy-to-use methods.
- **Efficient:** Every function in "pemmican" is optimized for performance. It's like getting your daily dose of crypto-vitamins in one go—no filler, all killer.
- **Versatile:** Whether you're trailblazing through the wilderness of web development or setting up camp in the back-end, "pemmican" has got your back. It's the all-in-one toolkit for your cryptographic needs.

So, if you're looking for a module that's as reliable and enduring as the food that fueled generations of adventurers, "pemmican" is your go-to source of crypto-nutrition. Feed your apps the good stuff, and watch them thrive in the wild untamed expanses of the internet.

Remember, in the digital wilderness, "pemmican" is the survival kit you didn't know you needed—until now.

## Getting Started

Before you can harness the power of "pemmican", you'll need to import it into your Deno project. Here's how you can do it:

### Generating a Key Pair
Generate a public/private key pair to start securing your application.
```typescript
import { CryptoUtils } from 'https://raw.githubusercontent.com/sebringj/pemmican/main/mod.ts';

async function generateKeys() {
  const { publicKeyPem, privateKeyPem } = await CryptoUtils.generateKeyPair();
  console.log('Public Key:', publicKeyPem);
  console.log('Private Key:', privateKeyPem);
}

generateKeys();
```

### Signing Data
Sign a piece of data using your private key, ensuring that it can be verified by the recipient.
```typescript
async function signMessage() {
  const { privateKeyPem } = await CryptoUtils.generateKeyPair(); // Assume privateKeyPem is obtained
  const data = 'Hello, Pemmican!';
  const { signatureBase64, timeStampISO } = await CryptoUtils.signData({ data, privateKeyPem });
  console.log('Signature:', signatureBase64);
  console.log('Timestamp:', timeStampISO);
}

signMessage();
```
