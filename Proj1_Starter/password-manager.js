"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor() {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
        kvs: {}, // key-value store
        salt: null // salt used to derive the master key
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */

      // storage of the derived master key
      masterKey: null, 
      // storage of the derived AES key
      aesKey: null,     
    };
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    // step 1: Generate a random salt
    let salt = getRandomBytes(16); // Generate a 128-bit salt (16 bytes)

    // step 2: Derive an encryption key from the password { Using PBKDF2 }(SubtleCrypto)
    let keyMaterial = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    // Step 3: Derive two keys from the key material using HMAC and AES-GCM
    let masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"]
    );

    // Step 4: Create a second key for AES-GCM encryption
    let aesKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 }, // AES-GCM key length is 256 bits
      false, // non-extractable
      ["encrypt", "decrypt"] // Only for encryption and decryption
    );

    let keychain = new Keychain();
    keychain.secrets.masterKey = masterKey; // Store the HMAC master key in the keychain privately
    keychain.secrets.aesKey = aesKey; // Store the AES key in the keychain privately
    keychain.data.salt = encodeBuffer(salt); // Store the salt in the keychain privately
    
    return keychain;
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    // Step 1: Deserialize the repr
    let parsedData = JSON.parse(repr); // parsedData is an array of two strings

    if(!parsedData.salt) {
      throw new Error("Missing salt in the provided representation");
    }

    try{
      // Extract the salt from the parsedData
      let salt = decodeBuffer(parsedData.salt); // salt is stored at index 0 and is stored as a Base64 encoded string

      // Step 2: Derive master key { Using PBKDF2 }(SubtleCrypto) and the provided password
      let keyMaterial = await subtle.importKey(
        "raw",
        stringToBuffer(password), // Converting string to buffer
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );

      let masterKey = await subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: PBKDF2_ITERATIONS,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        ["sign", "verify"]
      );

      let aesKey = await subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: PBKDF2_ITERATIONS,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 }, // AES-GCM key length is 256 bits
        false, // non-extractable
        ["encrypt", "decrypt"] // Only for encryption and decryption
      );

      // Step 3: Validate the intergrity of the data of a checksum is provided
      if (trustedDataCheck) {
        let computedHashBuffer = await subtle.digest("SHA-256", stringToBuffer(repr)); // hash of the data
        let computedCheckSum = encodeBuffer(computedHashBuffer); // hashCheck is the hash of the data
        if (computedCheckSum !== trustedDataCheck) {
          throw "Integrity check failed!";
        }
      }

      // Step 4: Create a new Keychain object and return it
      let keychain = new Keychain();
      keychain.data.kvs = parsedData.kvs // Load the key-value store
      keychain.data.salt = encodeBuffer(salt); // Store the salt

      // Store the derived master key (it's a  secret, so store it in keychains.secrets)
      keychain.secrets.masterKey = masterKey; // Store the master key in the keychain privately
      keychain.secrets.aesKey = aesKey; // Store the AES key in the keychain privately

      // Step 5: Return the keychain object
      return keychain;

    }catch(e){
      // If decryption or key derivation fails, return false or handle the error
      throw "Failed to load keychain with the provided password.";
    }
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    // Step 1: Serialize the KVS into JSON
    let serializedKVS = JSON.stringify({
      kvs: this.data.kvs, // Store the key-value store
      salt: this.data.salt // Store the salt
    });

    // Step 2: Generate a SHA-256 checksum of the serialized KVS
    let hashBuffer = await subtle.digest("SHA-256", stringToBuffer(serializedKVS));
    let checksum = encodeBuffer(hashBuffer);  // Encode the hash as Base64

    // Return an array with serialized data and the checksum
    return [serializedKVS, checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    // Step 1: Hash the domain name to retrieve the hashed key
    let hmac = await subtle.sign(
      "HMAC", 
      this.secrets.masterKey, 
      stringToBuffer(name)  // Convert domain name to buffer
    );
    let hashedName = encodeBuffer(hmac);

    // Step 2: Check if the hashedName exists in the KVS
    let record = this.data.kvs[hashedName];
    if (!record) return null;  // Return null if the domain is not found

    // Step 3: Decrypt the password
    let iv = decodeBuffer(record.iv); // Decode the IV from Base64
    let ciphertext = decodeBuffer(record.ciphertext); // Decode the ciphertext from Base64

    // Decrypt the ciphertext using AES-GCM
    let decryptedBuffer = await subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        this.secrets.aesKey,
        ciphertext
    );

    return bufferToString(decryptedBuffer);  // Convert decrypted buffer to string and return
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    // Step 1: Hash the domain name using HMAC
    let hmac = await subtle.sign(
        "HMAC",
        this.secrets.masterKey,  // Use the master key for HMAC
        stringToBuffer(name)  // Convert domain name to a buffer
    );
    let hashedName = encodeBuffer(hmac);  // Encode the HMAC as Base64

    // Step 2: Encrypt the password using AES-GCM

    // Generate a random IV for AES-GCM encryption
    let iv = getRandomBytes(12);  // AES-GCM typically uses a 96-bit (12-byte) IV

    // Use the master key directly for AES-GCM encryption
    let ciphertext = await subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        this.secrets.aesKey, // Use the AES-GCM master key for encryption
        stringToBuffer(value)  // Convert the password to a buffer
    );

    // Step 3: Store the encrypted password and IV in the key-value store (KVS)
    this.data.kvs[hashedName] = {
        ciphertext: encodeBuffer(ciphertext),  // Encrypt and store
        iv: encodeBuffer(iv)  // Store IV for decryption later
    };
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    // Step 1: Hash the domain name using HMAC
    let hmac = await subtle.sign(
      "HMAC", 
      this.secrets.masterKey, 
      stringToBuffer(name)
    );
    let hashedName = encodeBuffer(hmac);

    // Step 2: Check if the hashedName exists in the KVS and remove it
    if (this.data.kvs && this.data.kvs[hashedName]) {
        delete this.data.kvs[hashedName];  // Remove the entry
        return true;  // Return true if successfully removed
    }
    return false;  // Return false if the domain name doesn't exist
  };
};

module.exports = { Keychain }
