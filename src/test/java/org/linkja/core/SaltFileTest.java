package org.linkja.core;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class SaltFileTest {

  @Test
  void setMinSaltLength_Invalid() {
    SaltFile file = new SaltFile();
    assertThrows(LinkjaException.class, () -> file.setMinSaltLength(-1));
  }

  @Test
  void setMinSaltLength_Valid() throws LinkjaException {
    SaltFile file = new SaltFile();
    assertEquals(SaltFile.ABS_MIN_SALT_LENGTH, file.getMinSaltLength());
    file.setMinSaltLength(100);
    assertEquals(100, file.getMinSaltLength());
  }

  @Test
  void decrypt_null() {
    SaltFile file = new SaltFile();
    assertThrows(LinkjaException.class, () -> file.decrypt(null, null));
  }

  @Test
  void decrypt_invalid() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File privateKeyFile = new File(classLoader.getResource("private-test.key").toURI());
    File encryptedSaltFile = new File(classLoader.getResource("invalid_encrypted_salt.txt").toURI());
    SaltFile file = new SaltFile();
    assertThrows(javax.crypto.BadPaddingException.class, () -> file.decrypt(encryptedSaltFile, privateKeyFile));
  }

  @Test
  void decrypt_valid() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File privateKeyFile = new File(classLoader.getResource("private-test.key").toURI());
    File encryptedSaltFile = new File(classLoader.getResource("encrypted_salt.txt").toURI());
    File decryptedSaltFile = new File(classLoader.getResource("unencrypted_salt.txt").toURI());
    String[] saltFileContents = Files.readAllLines(decryptedSaltFile.toPath()).get(0).split(",");

    SaltFile file = new SaltFile();
    file.decrypt(encryptedSaltFile, privateKeyFile);
    assertEquals(saltFileContents[0], file.getSiteId());
    assertEquals(saltFileContents[1], file.getSiteName());
    assertEquals(saltFileContents[2], file.getPrivateSalt());
    assertEquals(saltFileContents[3], file.getProjectSalt());
    assertEquals(saltFileContents[4], file.getProjectName());
  }

  @Test
  void decrypt_saltTooShort() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File privateKeyFile = new File(classLoader.getResource("private-test.key").toURI());
    File encryptedSaltFile = new File(classLoader.getResource("encrypted_salt.txt").toURI());
    SaltFile file = new SaltFile();
    file.setMinSaltLength(10000);
    assertThrows(LinkjaException.class, () -> file.decrypt(encryptedSaltFile, privateKeyFile));
  }

  @Test
  void getSaltFileName_NullEmpty() {
    SaltFile engine = new SaltFile();
    LinkjaException exception = assertThrows(LinkjaException.class, () -> engine.getSaltFileName(null, "ok"));
    assertTrue(exception.getMessage().equals("The project name cannot be empty"));
    exception = assertThrows(LinkjaException.class, () -> engine.getSaltFileName("", "ok"));
    assertTrue(exception.getMessage().equals("The project name cannot be empty"));
    exception = assertThrows(LinkjaException.class, () -> engine.getSaltFileName("ok", null));
    assertTrue(exception.getMessage().equals("The site ID cannot be empty"));
    exception = assertThrows(LinkjaException.class, () -> engine.getSaltFileName("ok", ""));
    assertTrue(exception.getMessage().equals("The site ID cannot be empty"));
  }

  @Test
  void getSaltFileName_ValidParameters() throws LinkjaException {
    SaltFile engine = new SaltFile();
    assertTrue(engine.getSaltFileName("1", "2").startsWith("1_2_"));
    assertTrue(engine.getSaltFileName("project1", "001").startsWith("project1_001_"));
  }

  @Test
  void getSaltFileName_ReplaceCharacters() throws LinkjaException {
    SaltFile engine = new SaltFile();
    assertTrue(engine.getSaltFileName(" _ & 0zee ", "1 !!!").startsWith("_0zee_1_"));
    //TODO - ideally we should make sure after stripping invalid characters we're left with something. Maybe in the future?
    assertTrue(engine.getSaltFileName("*@()(#)$ ", " !!!").startsWith("__"));
  }

  @Test
  void encrypt() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File publicKeyFile = new File(classLoader.getResource("public-key-1.pem").toURI());
    File privateKeyFile = new File(classLoader.getResource("private-key-1.pem").toURI());
    File testFile = File.createTempFile("test", ".txt");  // Gives us a known temp folder
    testFile.deleteOnExit();

    Site site = new Site("001", "Test Site", publicKeyFile);
    Path rootPath = testFile.getParentFile().toPath();

    SaltFile engine = new SaltFile();
    engine.setProjectName("Test Project");
    engine.generateSaltFile(site, "0123456789123", rootPath);
    String saltFileName = engine.getSaltFileName(engine.getProjectName(), site.getSiteID());

    CryptoHelper helper = new CryptoHelper();
    String data = new String(helper.decryptRSA(Paths.get(rootPath.toString(), saltFileName).toFile(), privateKeyFile));
    assertTrue(data.startsWith("001,Test Site,"));
    assertTrue(data.endsWith(",Test Project"));
  }
}