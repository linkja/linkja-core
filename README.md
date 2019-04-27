# linkja-core

This project contains classes shared across the linkja applications. Additional documentation is also provided regarding implementations regarding  [encryption](#encryption), and [exception handling](#exception-handling).

## Building
linkja-core was built using Java JDK 10 (specifically [OpenJDK](https://openjdk.java.net/)).  It can be opened from within an IDE like Eclipse or IntelliJ IDEA and compiled, or compiled from the command line using [Maven](https://maven.apache.org/).

`mvn clean package`

This will compile the code, run all unit tests, and create a distributable JAR file under the .\target folder.  The JAR will be named something like `linkja-core-1.0.jar`.


## Deploying to Maven Repository
Linkja uses the [linkja-mvn-repo](https://github.com/linkja/linkja-mvn-repo) GitHub repository as its Maven repository for project builds.

The associated linkja projects that use linka-core will contain a reference to the GitHub repository in their pom.xml file.  Updates will need to be made to the linkja-mvn-repo and pushed to the master branch before projects will pick them up.

If you plan to build and deploy linkja-core, it's recommended you clone both of the repositories into the same directory.  For example:

```
/Users/me/Development/
  - linkja/
    - linkja-core/
    - linkja-mvn-repo/
```

After building the JAR, you would deploy it to the local copy of the linkja-mvn-repo repository using the following command:

`mvn deploy`

Finally, you will need to commit the changes made in linkja-mvn-repo, and push the changes to the master branch in GitHub.  Your other projects (e.g., linkja-hashing) should now be able to pull down the new version.

If you are updating an existing version of linkja-core and not bumping the version (discouraged, but just in case...), remember that your local projects will have cached the Maven dependencies.  You will need to force the Maven dependencies to be pulled back down.  From your project, like linkja-hashing, run the following command:

`mvn clean install -U`

## Implementation Details
### Encryption
There are two types of encryption being handled within linkja.  This includes asymmetric encryption using RSA, and symmetric encryption using AES.  Each of the following implementations are described in more detail, and is centrally implemented within the [CryptoHelper](src/main/java/org/linkja/core/CryptoHelper.java) class

#### Asymmetric Encryption
Asymmetric encryption is built using RSA public and private key pairs.  It assumes a minimum of a 1024-bit RSA key.  RSA is used to manage the encryption of salt files used by sites for individual projects, as well as for encrypting generated AES keys (described under [Symmetric Encryption](#symmetric-encryption)).

Because of how different systems can generate public and private keys, we are using the [Bouncy Castle](http://www.bouncycastle.org/) library to read in the public and private keys. Specifically we are specifying `RSA/ECB/PKCS1Padding` as our algorithm implementation.

#### Symmetric Encryption
Symmetric encryption is performed using AES-GCM-256 (algorithm reference including padding is `AES/GCM/PKCS5Padding`).  In addition to general `encryptAES` and `decryptAES` methods, there are additional methods to help linkja generate an AES key.

AES key generation is done as part of a [hybrid crypto](https://en.wikipedia.org/wiki/Hybrid_cryptosystem) approach.  A symmetric key is randomly generated, and then signed using a public key.  The exact approach to implement this is as follows:

1. Call `generateAESParameters` to securely generate a 256-bit key, as well as a 64-byte initialization vector (IV).  GCM is configured with a 128-bit authentication tag, and the IV.
2. `rsaEncryptAES` takes the AES parameters generated in step 1 and creates an encrypted binary file as output.  To generate the encrypted file, we create a byte array in memory that is 96 bytes in length.  The first 32 bytes of this array are the key, and the remaining 64 bytes are the IV.  Note that this is a contiguous block of memory with no delimiter.  This byte array is then encrypted using the provided RSA public key, and the encrypted data is written to a binary file on disk.
3. Encryption of a file is done with `encryptAES`.  This takes the AES key and IV, an input file (the file to be encrypted), and generates an encrypted binary file. When we initialize the [Cipher](https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html) object, we provide the keys as well as the authentication tag data.  As of now, we are using a single string as the authentication tag across all uses of the encryption library.  The input file is read in chunks of 8192 bytes.  This chunk is then encrypted and streamed to the output file as binary data.  This allows us to stream the data for encryption, as opposed to reading the entire file into memory.
4. Decryption of a file assumes you have an RSA-encrypted key file, along with an AES-encrypted data file.  The first step is to use the RSA private key to decrypt the AES key file.  This can be done using `rsaDecryptAES`.  This will create in memory the 256-bit AES key and the 64 byte IV.
5. Performing the decryption of the data file can be done via `decryptAES`.  As a reverse of step 3, this will read in 8192 byte chunks and decrypt them.  The decrypted chunks are then written to an output file on disk.

### Exception Handling
Within linkja, the [LinkjaException](src/main/java/org/linkja/core/LinkjaException.java) is intended to be a "safe", user-friendly representation of any particular exception situation.  This means that it should contain intuitive messages with sufficient information for the user to act on.  Any program catching a LinkjaException should be able to catch and display the message to the user.  Please keep this in mind when building and formatting exception messages.