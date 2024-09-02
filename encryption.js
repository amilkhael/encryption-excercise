/**
 * Key generation example
 * https://playcode.io/javascript
 */
import * as CryptoJS from "crypto-js";
async function generateKeyPair() {
  const keyGenOptions = {
    name: "ECDSA",
    namedCurve: "P-256",
  };

  try {
    const keyPair = await crypto.subtle.generateKey(keyGenOptions, true, [
      "sign",
      "verify",
    ]);
    console.log("Public key:", keyPair.publicKey);
    console.log("Private key:", keyPair.privateKey);
    return keyPair;
  } catch (error) {
    console.error("Error generating key pair:", error);
    throw error;
  }
}

/**
 * Digital Signature example
 */
async function signMessage(privateKey, message) {
  try {
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      new TextEncoder().encode(message)
    );
    console.log("Signature:", signature);
    return signature;
  } catch (error) {
    console.error("Error signing message:", error);
    throw error;
  }
}

async function verifySignature(publicKey, message, signature) {
  try {
    const verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      signature,
      new TextEncoder().encode(message)
    );
    return verified;
  } catch (error) {
    console.error("Error verifying signature:", error);
    throw error;
  }
}

// Usage example:
async function main() {
  try {
    const keyPair = await generateKeyPair();
    const signature = await signMessage(
      keyPair.privateKey,
      "Hello, Digital Signature!"
    );
    const verifiedSignature = await verifySignature(
      keyPair.publicKey,
      "Hello, Digital Signature!",
      signature
    );

    if (verifiedSignature) {
      console.log("Signature verified successfully.");
    } else {
      console.error("Signature verification failed.");
    }
  } catch (error) {
    console.error("Error occurred:", error);
  }
}

main();

/**
 * Symmetric Encryption example
 */
async function encryptData(data, key) {
  try {
    const encryptedData = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(12) },
      key,
      data
    );
    console.log("Encrypted data:", encryptedData);
    return encryptedData;
  } catch (error) {
    console.error("Error encrypting data:", error);
  }
}

/**
 * Symmetric Decryption example
 */
async function decryptData(encryptedData, key) {
  try {
    const decryptedData = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(12) },
      key,
      encryptedData
    );
    console.log("Decrypted data:", decryptedData);
    return decryptedData;
  } catch (error) {
    console.error("Error decrypting data:", error);
  }
}

// Usage example:
async function symmetricEncryptionExample() {
  try {
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const data = new TextEncoder().encode("Hello, Symmetric Encryption!");
    const encryptedData = await encryptData(data, key);
    const decryptedData = await decryptData(encryptedData, key);
    console.log("Decrypted data:", new TextDecoder().decode(decryptedData));
  } catch (error) {
    console.error("Error occurred:", error);
  }
}

symmetricEncryptionExample();
