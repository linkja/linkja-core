package org.linkja.core;

import org.junit.jupiter.api.Test;
import org.linkja.core.crypto.CryptoHelper;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

class CryptoHelperTest {

  @Test
  void generateAESParameters() throws NoSuchAlgorithmException {
    CryptoHelper helper = new CryptoHelper();
    CryptoHelper.AESParameters params1 = helper.generateAESParameters();
    assertNotNull(params1.Key);
    assertNotNull(params1.GCMParams);
    assertNotNull(params1.GCMParams.getIV());

    // Must not generate the same parameters twice (it's supposed to be random)
    // This is a superficial check, since validation of randomness would take significantly more iterations.  This
    // isn't meant to be a security check, just cursory validation that running it twice gives "different" results.
    CryptoHelper.AESParameters params2 = helper.generateAESParameters();
    assertNotEquals(params1.Key, params2.Key);
    assertNotEquals(params1.GCMParams.getIV(), params2.GCMParams.getIV());

    // Similarly, recreating the object should still produce different results (RNG shouldn't start with the same seed)
    CryptoHelper helper2 = new CryptoHelper();
    CryptoHelper.AESParameters params3 = helper2.generateAESParameters();
    assertNotEquals(params1.Key, params3.Key);
    assertNotEquals(params1.GCMParams.getIV(), params3.GCMParams.getIV());
  }

  @Test
  void rsa_aesKeyRoundtrip() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File publicKeyFile = new File(classLoader.getResource("public-test.key").toURI());
    File privateKeyFile = new File(classLoader.getResource("private-test.key").toURI());
    File output = File.createTempFile("linkja-core-test-output", ".bin");
    File decryptTest = File.createTempFile("linkja-core-test-decrypt", ".txt");
    output.deleteOnExit();
    decryptTest.deleteOnExit();

    CryptoHelper helper = new CryptoHelper();
    CryptoHelper.AESParameters parameters = helper.generateAESParameters();
    helper.rsaEncryptAES(parameters, output, publicKeyFile);
    CryptoHelper.AESParameters decryptedAES = helper.rsaDecryptAES(output, privateKeyFile);
    assertEquals(parameters.Key, decryptedAES.Key);
    assertArrayEquals(parameters.GCMParams.getIV(), decryptedAES.GCMParams.getIV());
  }

  @Test
  void aes_roundtrip() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException {
    final String DATA = "This is a sample set of data";
    File input = File.createTempFile("linkja-core-test-input", ".txt");
    File output = File.createTempFile("linkja-core-test-output", ".bin");
    File decryptTest = File.createTempFile("linkja-core-test-decrypt", ".txt");
    input.deleteOnExit();
    output.deleteOnExit();
    decryptTest.deleteOnExit();

    CryptoHelper helper = new CryptoHelper();
    CryptoHelper.AESParameters parameters = helper.generateAESParameters();
    Files.write(input.toPath(), DATA.getBytes());
    helper.encryptAES(parameters, input, output);
    helper.decryptAES(parameters, output, decryptTest);
    String result = String.join("", Files.readAllLines(decryptTest.toPath()));
    assertEquals(DATA, result);
  }

  @Test
  void rsa_roundtrip() throws Exception {
    final String DATA = "This is a sample set of data";
    ClassLoader classLoader = getClass().getClassLoader();
    File publicKeyFile = new File(classLoader.getResource("public-test.key").toURI());
    File privateKeyFile = new File(classLoader.getResource("private-test.key").toURI());

    CryptoHelper helper = new CryptoHelper();
    byte[] encryptedData = helper.encryptRSA(DATA.getBytes(), publicKeyFile);
    byte[] decryptedData = helper.decryptRSA(encryptedData, privateKeyFile);
    String decryptedString = new String(decryptedData);
    assertEquals(DATA, decryptedString);
  }

  @Test
  void getRSAPrivateKey_Invalid() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File privateKeyFile = new File(classLoader.getResource("invalid-test.key").toURI());
    CryptoHelper helper = new CryptoHelper();
    assertThrows(Exception.class, () -> helper.getRSAPrivateKey(privateKeyFile));
  }

  @Test
  void getRSAPrivateKey_Valid() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File privateKeyFile = new File(classLoader.getResource("private-test.key").toURI());
    CryptoHelper helper = new CryptoHelper();
    KeyPair privateKey = helper.getRSAPrivateKey(privateKeyFile);
    assertNotNull(privateKey);
    assertNotNull(privateKey.getPrivate());
  }

  @Test
  void getRSAPublicKey_Invalid() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File publicKeyFile = new File(classLoader.getResource("invalid-test.key").toURI());
    CryptoHelper helper = new CryptoHelper();
    assertThrows(Exception.class, () -> helper.getRSAPublicKey(publicKeyFile));
  }

  @Test
  void getRSAPublicKey_Valid() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File publicKeyFile = new File(classLoader.getResource("public-test.key").toURI());
    CryptoHelper helper = new CryptoHelper();
    PublicKey publicKey = helper.getRSAPublicKey(publicKeyFile);
    assertNotNull(publicKey);
  }
}
