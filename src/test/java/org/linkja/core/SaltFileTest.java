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
    assertEquals(saltFileContents[0], file.getSiteID());
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
  void load_null() {
    SaltFile file = new SaltFile();
    assertThrows(LinkjaException.class, () -> file.load(null));
  }

  @Test
  void load_invalid() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File saltFile = new File(classLoader.getResource("invalid_salt.txt").toURI());
    SaltFile file = new SaltFile();
    assertThrows(LinkjaException.class, () -> file.load(saltFile));
  }

  @Test
  void load_valid() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File saltFile = new File(classLoader.getResource("unencrypted_salt.txt").toURI());
    String[] saltFileContents = Files.readAllLines(saltFile.toPath()).get(0).split(",");

    SaltFile file = new SaltFile();
    file.load(saltFile);
    assertEquals(saltFileContents[0], file.getSiteID());
    assertEquals(saltFileContents[1], file.getSiteName());
    assertEquals(saltFileContents[2], file.getPrivateSalt());
    assertEquals(saltFileContents[3], file.getProjectSalt());
    assertEquals(saltFileContents[4], file.getProjectName());
  }

  @Test
  void save_null() {
    SaltFile file = new SaltFile();
    assertThrows(LinkjaException.class, () -> file.save(null));
  }

  @Test
  void save_valid() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();

    // Load the gold standard
    File saltFile = new File(classLoader.getResource("unencrypted_salt.txt").toURI());
    String validSaltFileContents = Files.readAllLines(saltFile.toPath()).get(0);

    // Create a SaltFile object from that content
    SaltFile file = new SaltFile();
    file.load(saltFile);

    // Call the save method.  Yes it's the same content, but that's the test.  We just want
    // it to write to another file.
    File tempFile = File.createTempFile("salt-", ".txt");
    tempFile.deleteOnExit();
    file.save(tempFile);

    // Reload to see what we wrote
    String saltFileContents = Files.readAllLines(tempFile.toPath()).get(0);

    // Make sure it's the same
    assertEquals(validSaltFileContents, saltFileContents);
  }

  @Test
  void getSaltFileName_NullEmpty() {
    SaltFile file = new SaltFile();
    LinkjaException exception = assertThrows(LinkjaException.class, () -> file.getSaltFileName(null, "ok"));
    assertTrue(exception.getMessage().equals("The project name cannot be empty"));
    exception = assertThrows(LinkjaException.class, () -> file.getSaltFileName("", "ok"));
    assertTrue(exception.getMessage().equals("The project name cannot be empty"));
    exception = assertThrows(LinkjaException.class, () -> file.getSaltFileName("ok", null));
    assertTrue(exception.getMessage().equals("The site ID cannot be empty"));
    exception = assertThrows(LinkjaException.class, () -> file.getSaltFileName("ok", ""));
    assertTrue(exception.getMessage().equals("The site ID cannot be empty"));
  }

  @Test
  void getSaltFileName_ValidParameters() throws LinkjaException {
    SaltFile file = new SaltFile();
    assertTrue(file.getSaltFileName("1", "2").startsWith("1_2_"));
    assertTrue(file.getSaltFileName("project1", "001").startsWith("project1_001_"));
  }

  @Test
  void getSaltFileName_ReplaceCharacters() throws LinkjaException {
    SaltFile file = new SaltFile();
    assertTrue(file.getSaltFileName(" _ & 0zee ", "1 !!!").startsWith("_0zee_1_"));
    //TODO - ideally we should make sure after stripping invalid characters we're left with something. Maybe in the future?
    assertTrue(file.getSaltFileName("*@()(#)$ ", " !!!").startsWith("__"));
  }

  @Test
  void encrypt() throws Exception {
    ClassLoader classLoader = getClass().getClassLoader();
    File publicKeyFile = new File(classLoader.getResource("public-test.key").toURI());
    File privateKeyFile = new File(classLoader.getResource("private-test.key").toURI());
    File testFile = File.createTempFile("test", ".txt");  // Gives us a known temp folder
    testFile.deleteOnExit();

    Site site = new Site("001", "Test Site");
    Path rootPath = testFile.getParentFile().toPath();

    SaltFile file = new SaltFile();
    file.setSite(site);
    file.setProjectName("Test Project");
    String saltFileName = file.getSaltFileName(file.getProjectName(), site.getSiteID());
    Path saltFilePath = Paths.get(rootPath.toString(), saltFileName);
    file.encrypt(saltFilePath.toFile(), publicKeyFile);

    CryptoHelper helper = new CryptoHelper();
    String data = new String(helper.decryptRSA(Paths.get(rootPath.toString(), saltFileName).toFile(), privateKeyFile));
    assertTrue(data.startsWith("001,Test Site,"));
    assertTrue(data.endsWith(",Test Project"));
  }
}
