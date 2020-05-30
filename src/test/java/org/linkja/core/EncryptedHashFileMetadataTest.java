package org.linkja.core;

import org.junit.jupiter.api.Test;
import org.linkja.core.crypto.AesEncryptParameters;

import java.io.*;
import java.net.URISyntaxException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class EncryptedHashFileMetadataTest {

    @Test
    void write_invalidSiteLength() throws URISyntaxException, IOException, LinkjaException {
      ClassLoader classLoader = getClass().getClassLoader();
      byte[] sessionKey = AesEncryptParameters.generate(32, 16, 128).getKey();

      // Initialize and write to memory the bytes for our metadata
      ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
      BufferedOutputStream outputStream = new BufferedOutputStream(byteStream);
      String siteId = new String(new char[EncryptedHashFileMetadata.INPUT_BUFFER_LENGTH + 1]).replace("\0", "a");
      EncryptedHashFileMetadata metadata = new EncryptedHashFileMetadata(siteId, "Test", 10, 1000, sessionKey, "ABCDEFG");
      assertThrows(LinkjaException.class, () -> metadata.write(outputStream, null));
    }

    @Test
    void write_invalidProjectLength() throws URISyntaxException, IOException, LinkjaException {
      ClassLoader classLoader = getClass().getClassLoader();
      byte[] sessionKey = AesEncryptParameters.generate(32, 16, 128).getKey();

      // Initialize and write to memory the bytes for our metadata
      ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
      BufferedOutputStream outputStream = new BufferedOutputStream(byteStream);
      String projectId = new String(new char[EncryptedHashFileMetadata.INPUT_BUFFER_LENGTH + 1]).replace("\0", "b");
      EncryptedHashFileMetadata metadata = new EncryptedHashFileMetadata("Test", projectId, 10, 1000, sessionKey, "ABCDEFG");
      assertThrows(LinkjaException.class, () -> metadata.write(outputStream, null));
    }

    @Test
    void write_read_fullCycle() throws URISyntaxException, IOException, LinkjaException {
      ClassLoader classLoader = getClass().getClassLoader();
      byte[] sessionKey = AesEncryptParameters.generate(32, 16, 128).getKey();
      String cryptoSignature = "ABCDABCDABCDABCDABCDABCDABCDABCD";

      // Initialize and write to memory the bytes for our metadata
      ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
      BufferedOutputStream outputStream = new BufferedOutputStream(byteStream);
      EncryptedHashFileMetadata metadata = new EncryptedHashFileMetadata("Test", "1234", 10, (Integer.MAX_VALUE * 10L), sessionKey, cryptoSignature);
      File publicKeyFile = new File(classLoader.getResource("public-test.key").toURI());
      metadata.write(outputStream, publicKeyFile);
      outputStream.flush();
      outputStream.close();
      byteStream.close();
      byte[] data = byteStream.toByteArray();


      // Now read those bytes back to a new metadata object
      ByteArrayInputStream byteInStream = new ByteArrayInputStream(data);
      BufferedInputStream inputStream = new BufferedInputStream(byteInStream);
      File privateKeyFile = new File(classLoader.getResource("private-test.key").toURI());
      EncryptedHashFileMetadata readMetadata = EncryptedHashFileMetadata.read(inputStream, privateKeyFile);

      assertEquals(metadata.getMetadataVersion(), readMetadata.getMetadataVersion());
      assertEquals(metadata.getSiteId(), readMetadata.getSiteId());
      assertEquals(metadata.getProjectId(), readMetadata.getProjectId());
      assertEquals(metadata.getNumHashColumns(), readMetadata.getNumHashColumns());
      assertEquals(metadata.getCryptoSignature(), readMetadata.getCryptoSignature());
      assertTrue(Arrays.equals(metadata.getSessionKey(), readMetadata.getSessionKey()));

      inputStream.close();
      byteInStream.close();
    }

  @Test
  void writeUpdatedNumHashRows() throws URISyntaxException, IOException, LinkjaException {
    ClassLoader classLoader = getClass().getClassLoader();
    byte[] sessionKey = AesEncryptParameters.generate(32, 16, 128).getKey();
    String cryptoSignature = "ABCDABCDABCDABCDABCDABCDABCDABCD";

    // Initialize and write to memory the bytes for our metadata
    File file = File.createTempFile("writeUpdatedNumHashRows", ".bin");
    file.deleteOnExit();
    FileOutputStream fileStream = new FileOutputStream(file);
    BufferedOutputStream outputStream = new BufferedOutputStream(fileStream);
    EncryptedHashFileMetadata metadata = new EncryptedHashFileMetadata("Test", "1234", 10, 0, sessionKey, cryptoSignature);
    File publicKeyFile = new File(classLoader.getResource("public-test.key").toURI());
    metadata.write(outputStream, publicKeyFile);
    outputStream.flush();
    outputStream.close();
    fileStream.close();

    long updatedNumHashRows = 51230439;
    metadata.setNumHashRows(updatedNumHashRows);
    metadata.writeUpdatedNumHashRows(file);


    // Now read those bytes back to a new metadata object
    FileInputStream fileInputStream = new FileInputStream(file);
    BufferedInputStream inputStream = new BufferedInputStream(fileInputStream);
    File privateKeyFile = new File(classLoader.getResource("private-test.key").toURI());
    EncryptedHashFileMetadata readMetadata = EncryptedHashFileMetadata.read(inputStream, privateKeyFile);

    assertEquals(updatedNumHashRows, readMetadata.getNumHashRows());

    assertEquals(metadata.getMetadataVersion(), readMetadata.getMetadataVersion());
    assertEquals(metadata.getSiteId(), readMetadata.getSiteId());
    assertEquals(metadata.getProjectId(), readMetadata.getProjectId());
    assertEquals(metadata.getNumHashColumns(), readMetadata.getNumHashColumns());
    assertEquals(metadata.getCryptoSignature(), readMetadata.getCryptoSignature());
    assertTrue(Arrays.equals(metadata.getSessionKey(), readMetadata.getSessionKey()));

    inputStream.close();
    fileInputStream.close();
  }
}
