package org.linkja.core;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Base64;

/**
 *
 * Credit to the following resources for education, inspiration as well as code used and adapted within this class.
 *   https://github.com/1MansiS/java_crypto/blob/master/cipher/SecuredGCMUsage.java
 *   https://stackoverflow.com/a/46828430
 *   https://stackoverflow.com/a/29532412
 *   https://stackoverflow.com/q/42501609
 *
 * Changes/refactoring were done to all of the code acknowledged that we were not able to use them directly, which
 * is why we don't have direct inclusion/attribution of those source files.
 */
public class CryptoHelper {
  private static int AES_KEY_SIZE_BITS = 256;
  private static int AES_KEY_SIZE_BYTES = AES_KEY_SIZE_BITS / 8;
  private static int IV_SIZE = 64;
  private static int TAG_BIT_LENGTH = 128;
  private static String AES_KEY_ALGORITHM = "AES";
  private static String AES_ENCRYPTION_ALGORITHM = "AES/GCM/PKCS5Padding";
  private static String RSA_ENCRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding";
  private static int CIPHER_OUTPUT_BUFFER_SIZE = 8192;

  private static final byte[] AAD_DATA = "org.linkja.core.CryptoHelper".getBytes();

  public class AESParameters {
    public GCMParameterSpec GCMParams = null;
    public SecretKey Key = null;
  }

  /**
   * Randomly generate the necessary parameters for calling AES encryption.  This uses a locally defined class to
   * represent the objects created during the process.
   * @return
   * @throws NoSuchAlgorithmException
   */
  public AESParameters generateAESParameters() throws NoSuchAlgorithmException {
    // Generating Key
    SecretKey aesKey = null;
    KeyGenerator keygen = KeyGenerator.getInstance(AES_KEY_ALGORITHM) ; // Specifying algorithm key will be used for
    keygen.init(AES_KEY_SIZE_BITS); // Specifying Key size to be used, Note: This would need JCE Unlimited Strength to be installed explicitly
    aesKey = keygen.generateKey();

    // Generating IV
    byte iv[] = new byte[IV_SIZE];
    SecureRandom secRandom = new SecureRandom();
    secRandom.nextBytes(iv); // SecureRandom initialized using self-seeding

    // Initialize GCM Parameters
    GCMParameterSpec gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv) ;

    AESParameters aesParameters = new AESParameters();
    aesParameters.Key = aesKey;
    aesParameters.GCMParams = gcmParamSpec;
    return aesParameters;
  }

  /**
   * Use a public RSA key to encrypt/sign the necessary parts of an AES key.  This is written as base64-encoded data
   * to a text file at the provided path.
   * @param publicKeyFile
   * @param aesParameters
   * @param outputFile
   * @throws Exception
   */
  public void rsaEncryptAES(AESParameters aesParameters, File outputFile, File publicKeyFile) throws Exception {
    BufferedReader reader = new BufferedReader(new FileReader(publicKeyFile));
    PEMParser parser = new PEMParser(reader);
    SubjectPublicKeyInfo spki = (SubjectPublicKeyInfo)parser.readObject();
    parser.close();
    reader.close();
    PublicKey publicKeyParam = new JcaPEMKeyConverter().getPublicKey(spki);

    byte[] unencryptedData = new byte[(AES_KEY_SIZE_BITS / 8) + IV_SIZE];
    System.arraycopy(aesParameters.Key.getEncoded(), 0, unencryptedData, 0, AES_KEY_SIZE_BYTES);
    System.arraycopy(aesParameters.GCMParams.getIV(), 0, unencryptedData, AES_KEY_SIZE_BYTES, IV_SIZE);

    Cipher encrypt = Cipher.getInstance(RSA_ENCRYPTION_ALGORITHM);
    encrypt.init(Cipher.PUBLIC_KEY, publicKeyParam);
    byte[] encryptedData = encrypt.doFinal(unencryptedData);
    Files.write(outputFile.toPath(), encryptedData);
  }

  /**
   * Given an encrypted file, and a private decryption key, get out the AES key and IV.
   * @param inputFile
   * @param privateKey
   * @return
   * @throws Exception
   */
  public AESParameters rsaDecryptAES(File inputFile, File privateKey) throws Exception {
    BufferedReader reader = new BufferedReader(new FileReader(privateKey));
    PEMParser parser = new PEMParser(reader);
    PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
    KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
    parser.close();
    reader.close();

    Cipher decrypt = Cipher.getInstance(RSA_ENCRYPTION_ALGORITHM);
    decrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    byte[] decryptedMessage = decrypt.doFinal(Files.readAllBytes(inputFile.toPath()));
    if (decryptedMessage == null || decryptedMessage.length != (AES_KEY_SIZE_BITS / 8) + IV_SIZE) {
      throw new InvalidKeyException("The provided AES key file is invalid.");
    }

    // At this point we have confirmed our assumption of the size of the data array, so memory access can be done
    // without issue.
    SecretKey key = new SecretKeySpec(decryptedMessage, 0, (AES_KEY_SIZE_BITS / 8), AES_KEY_ALGORITHM);
    byte[] iv = new byte[IV_SIZE];
    System.arraycopy(decryptedMessage, AES_KEY_SIZE_BYTES, iv, 0, IV_SIZE);
    GCMParameterSpec gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);

    AESParameters parameters = new AESParameters();
    parameters.Key = key;
    parameters.GCMParams = gcmParamSpec;
    return parameters;
  }

  /**
   * Perform AES-256 encryption on an input file, writing the encrypted binary data to disk as an output file
   * @param aesParameters
   * @param inputFile
   * @param outputFile
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidAlgorithmParameterException
   * @throws InvalidKeyException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws IOException
   */
  public void encryptAES(AESParameters aesParameters, File inputFile, File outputFile) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IOException {
    Cipher cipher = Cipher.getInstance(AES_ENCRYPTION_ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, aesParameters.Key, aesParameters.GCMParams, new SecureRandom());
    cipher.updateAAD(AAD_DATA); // add AAD tag data before encrypting

    BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
    BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
    CipherOutputStream out = new CipherOutputStream(outputStream, cipher);
    byte[] buffer = new byte[CIPHER_OUTPUT_BUFFER_SIZE];
    int count;
    while ((count = inputStream.read(buffer)) > 0) {
      out.write(buffer, 0, count);
    }

    out.flush();
    out.close();
    outputStream.close();
    inputStream.close();
  }

  /**
   * Perform AES-256 decryption on an input file, writing the plaintext to disk as an output file.
   * @param aesParameters
   * @param inputFile
   * @param outputFile
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws InvalidAlgorithmParameterException
   * @throws InvalidKeyException
   * @throws IOException
   */
  public void decryptAES(AESParameters aesParameters, File inputFile, File outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
    Cipher cipher = Cipher.getInstance(AES_ENCRYPTION_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, aesParameters.Key, aesParameters.GCMParams, new SecureRandom()) ;
    cipher.updateAAD(AAD_DATA) ; // Add AAD details before decrypting

    BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile));
    BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
    CipherInputStream in = new CipherInputStream(inputStream, cipher);
    byte[] buffer = new byte[CIPHER_OUTPUT_BUFFER_SIZE];
    int count;
    while ((count = in.read(buffer)) >= 0) {
      outputStream.write(buffer, 0, count);
    }

    in.close();
    outputStream.flush();
    outputStream.close();
    inputStream.close();
  }
}
