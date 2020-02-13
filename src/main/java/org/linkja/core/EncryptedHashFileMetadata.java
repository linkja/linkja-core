package org.linkja.core;

import org.linkja.core.crypto.AesEncryptParameters;
import org.linkja.crypto.Library;
import org.linkja.crypto.RsaResult;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;

public class EncryptedHashFileMetadata {
  private static final int METADATA_VERSION = 1;
  private static final byte[] METADATA_START_BLOCK = "-----BEGIN LINKJA HEADER-----".getBytes();
  private static final byte[] METADATA_END_BLOCK = "-----END LINKJA HEADER-----".getBytes();
  private static final byte[] ENVELOPE_START_BLOCK = "-----BEGIN LINKJA ENVELOPE-----".getBytes();
  private static final byte[] ENVELOPE_END_BLOCK = "-----END LINKJA ENVELOPE-----".getBytes();
  private static final byte BLOCK_DELIMITER = (byte)'\n';
  private static final int BLOCK_DELIMITER_LEN = 1;

  // We write integers into 4-byte blocks.  This will let our byte stream know how much to read back in.
  private static final int INT_BYTE_LEN = 4;

  private static final int MAX_ENCRYPTION_ALGORITHM_LENGTH = 15;

  public static final int INPUT_BUFFER_LENGTH = 1024;

  private int metadataVersion = METADATA_VERSION;
  private AesEncryptParameters encryptParameters;
  private String siteId;
  private String projectId;
  private int numHashColumns;
  private String encryptionAlgorithm;
  private int aesKeySize;
  private int aesIvSize;
  private int aesAadSize;

  public EncryptedHashFileMetadata() {
  }

  public EncryptedHashFileMetadata(String siteId, String projectId, int numHashColumns, AesEncryptParameters encryptParameters) {
    this.encryptParameters = encryptParameters;
    this.siteId = siteId;
    this.projectId = projectId;
    this.numHashColumns = numHashColumns;
    String encryptionAlgorithm = encryptParameters.getAlgorithmName();
    if (encryptionAlgorithm.length() > MAX_ENCRYPTION_ALGORITHM_LENGTH) {
      throw new IllegalArgumentException(String.format("The encryption algorithm cannot be longer than %d characters", MAX_ENCRYPTION_ALGORITHM_LENGTH));
    }
    this.encryptionAlgorithm = encryptionAlgorithm.trim();
    this.aesKeySize = encryptParameters.getKey().length;
    this.aesIvSize = encryptParameters.getIv().length;
    this.aesAadSize = encryptParameters.getAad().length;
  }

  public void write(BufferedOutputStream stream, File rsaPublicKey) throws IOException, LinkjaException {
    stream.write(METADATA_START_BLOCK);
    stream.write(BLOCK_DELIMITER);

    // Version metadata block
    writeInt(stream, metadataVersion);
    stream.write(BLOCK_DELIMITER);

    // Project and site metadata block
    if (siteId.length() > INPUT_BUFFER_LENGTH) {
      throw new LinkjaException(String.format("The site ID cannot exceed %d bytes, but is %d",
        INPUT_BUFFER_LENGTH, siteId.length()));
    }
    else if (projectId.length() > INPUT_BUFFER_LENGTH) {
      throw new LinkjaException(String.format("The project ID cannot exceed %d bytes, but is %d",
        INPUT_BUFFER_LENGTH, projectId.length()));
    }
    writeInt(stream, siteId.length());
    stream.write(siteId.getBytes());
    writeInt(stream, projectId.length());
    stream.write(projectId.getBytes());
    writeInt(stream, numHashColumns);
    stream.write(BLOCK_DELIMITER);

    // Encryption metadata block
    writeInt(stream, encryptionAlgorithm.length());
    stream.write(encryptionAlgorithm.getBytes());
    writeInt(stream, aesKeySize);
    writeInt(stream, aesIvSize);
    writeInt(stream, aesAadSize);
    stream.write(BLOCK_DELIMITER);

    stream.write(METADATA_END_BLOCK);
    stream.write(BLOCK_DELIMITER);

    // Now write out the symmetric key information
    stream.write(ENVELOPE_START_BLOCK);
    stream.write(BLOCK_DELIMITER);

    byte[] keyBytes = Files.readAllBytes(rsaPublicKey.toPath());
    RsaResult result = Library.rsaEncrypt(encryptParameters.getKey(), keyBytes);
    writeInt(stream, result.data.length);
    stream.write(result.data);
    result = Library.rsaEncrypt(encryptParameters.getIv(), keyBytes);
    writeInt(stream, result.data.length);
    stream.write(result.data);
    writeInt(stream, encryptParameters.getAad().length);
    stream.write(encryptParameters.getAad());
    stream.write(ENVELOPE_END_BLOCK);
    stream.write(BLOCK_DELIMITER);
  }

  public static EncryptedHashFileMetadata read(BufferedInputStream stream, File rsaPrivateKey) throws IOException, LinkjaException {
    EncryptedHashFileMetadata metadata = new EncryptedHashFileMetadata();
    readBlockNameFromStream(stream, "metadata start", METADATA_START_BLOCK);

    // Version metadata block
    int metadataVersion = readInt(stream, "Missing or invalid metadata version in header");
    // For now we only have one version, so it has to match exactly.  In the future this will need to be expanded to
    // handle version compatibility.
    if (metadataVersion != METADATA_VERSION) {
      throw new LinkjaException(String.format("Unknown version (%d) of metadata header format", metadataVersion));
    }
    metadata.setMetadataVersion(metadataVersion);
    readBlockDelimiter(stream, "metadata version");

    // Project and site metadata block
    String siteId = readStringFromStream(stream, "site ID");
    metadata.setSiteId(siteId);

    String projectId = readStringFromStream(stream, "project ID");
    metadata.setProjectId(projectId);

    int numHashColumns = readInt(stream, "Invalid number of hash values in header");
    if (numHashColumns <= 0) {
      throw new LinkjaException(String.format("Invalid number of hash values in header - there must be at least one, but found %d", numHashColumns));
    }
    metadata.setNumHashColumns(numHashColumns);

    readBlockDelimiter(stream, "project and site metadata");

    // Encryption metadata block
    String encryption = readStringFromStream(stream, "encryption algorithm");
    if (!encryption.equals(AesEncryptParameters.ALGORITHM_NAME)) {
      throw new LinkjaException(String.format("Invalid encryption algorithm (%s) in header.  Currently only %s is supported.", encryption, AesEncryptParameters.ALGORITHM_NAME));
    }
    metadata.setEncryptionAlgorithm(encryption);

    int aesKeySize = readInt(stream, "Invalid encryption key size in header");
    if (aesKeySize <= 0) {
      throw new LinkjaException("Invalid encryption key length (too short) in header");
    }
    metadata.setAesKeySize(aesKeySize);

    int aesIvSize = readInt(stream, "Invalid encryption IV size in header");
    if (aesIvSize <= 0) {
      throw new LinkjaException("Invalid encryption IV length (too short) in header");
    }
    metadata.setAesIvSize(aesIvSize);

    int aesAadSize = readInt(stream, "Invalid encryption AAD size in header");
    if (aesAadSize <= 0) {
      throw new LinkjaException("Invalid encryption AAD length (too short) in header");
    }
    metadata.setAesAadSize(aesAadSize);

    readBlockDelimiter(stream, "encryption metadata");

    readBlockNameFromStream(stream, "metadata end", METADATA_END_BLOCK);

    readBlockNameFromStream(stream, "envelope start", ENVELOPE_START_BLOCK);

    byte[] rsaPrivateKeyBytes = Files.readAllBytes(rsaPrivateKey.toPath());
    byte[] aesKey = readAndDecryptFromStream(stream, rsaPrivateKeyBytes, "encryption key", aesKeySize);
    byte[] aesIv = readAndDecryptFromStream(stream, rsaPrivateKeyBytes, "encryption IV", aesIvSize);
    byte[] aesAad = readByteArrayFromStream(stream, "encryption AAD");
    if (aesAad.length != aesAadSize) {
      throw new LinkjaException("The encryption AAD was corrupted and could not be read from the header");
    }

    AesEncryptParameters parameters = new AesEncryptParameters(aesKey, aesIv, aesAad);
    metadata.setEncryptParameters(parameters);

    readBlockNameFromStream(stream, "envelope end", ENVELOPE_END_BLOCK);

    return metadata;
  }

  private static void readBlockNameFromStream(BufferedInputStream stream, String blockName, byte[] blockValue) throws IOException, LinkjaException {
    byte[] buffer = new byte[blockValue.length];
    int result = stream.read(buffer, 0, blockValue.length);
    if (result != blockValue.length) {
      throw new LinkjaException(String.format("Invalid %s block in header", blockName));
    }

    readBlockDelimiter(stream, String.format("%s block in header", blockName));
  }

  private static byte[] readAndDecryptFromStream(BufferedInputStream stream, byte[] rsaPrivateKey, String dataElementName, int expectedLength) throws LinkjaException, IOException {
    byte[] data = readByteArrayFromStream(stream, dataElementName);
    RsaResult decryptResult = Library.rsaDecrypt(data, rsaPrivateKey);
    if (decryptResult.length != expectedLength) {
      throw new LinkjaException(String.format("The %s was corrupted and could not be read from the header", dataElementName));
    }

    return decryptResult.data;
  }

  private static String readStringFromStream(BufferedInputStream stream, String dataElementName) throws LinkjaException, IOException {
    byte[] data = readByteArrayFromStream(stream, dataElementName);
    String string = new String(data, 0, data.length);
    return string;
  }

  private static byte[] readByteArrayFromStream(BufferedInputStream stream, String dataElementName) throws LinkjaException, IOException {
    int dataSize = readInt(stream, String.format("Invalid %s length in header", dataElementName));
    if (dataSize <= 0) {
      throw new LinkjaException(String.format("Invalid %s length (too short) in header", dataElementName));
    }
    byte[] buffer = new byte[dataSize];
    int result = stream.read(buffer, 0, dataSize);
    if (result != dataSize) {
      throw new LinkjaException(String.format("Invalid %s in header", dataElementName));
    }

    return buffer;
  }

  /**
   * Writes the 32-bit int to the binary output stream.
   * @param x the {@code int} to write
   */
  private static void writeInt(BufferedOutputStream stream, int x) throws IOException {
    stream.write((x >>> 24) & 0xff);
    stream.write((x >>> 16) & 0xff);
    stream.write((x >>>  8) & 0xff);
    stream.write((x >>>  0) & 0xff);
  }

  private static int readInt(BufferedInputStream stream, String exceptionMessage) throws LinkjaException, IOException {
    byte[] buffer = new byte[INT_BYTE_LEN];
    int result = stream.read(buffer, 0, INT_BYTE_LEN);
    if (result != INT_BYTE_LEN) {
      throw new LinkjaException(exceptionMessage);
    }

    int value = ByteBuffer.wrap(buffer, 0, INT_BYTE_LEN).getInt();
    return value;
  }

  private static void readBlockDelimiter(BufferedInputStream stream, String position) throws IOException, LinkjaException {
    byte[] buffer = new byte[BLOCK_DELIMITER_LEN];
    int result = stream.read(buffer, 0, BLOCK_DELIMITER_LEN);
    if (result != BLOCK_DELIMITER_LEN || buffer[0] != BLOCK_DELIMITER) {
      throw new LinkjaException(String.format("Missing or invalid delimiter after %s", position));
    }
  }

  public int getMetadataVersion() {
    return metadataVersion;
  }

  public void setMetadataVersion(int metadataVersion) {
    this.metadataVersion = metadataVersion;
  }

  public AesEncryptParameters getEncryptParameters() {
    return encryptParameters;
  }

  public void setEncryptParameters(AesEncryptParameters encryptParameters) {
    this.encryptParameters = encryptParameters;
  }

  public String getSiteId() {
    return siteId;
  }

  public void setSiteId(String siteId) {
    this.siteId = siteId;
  }

  public String getProjectId() {
    return projectId;
  }

  public void setProjectId(String projectId) {
    this.projectId = projectId;
  }

  public int getNumHashColumns() {
    return numHashColumns;
  }

  public void setNumHashColumns(int numHashColumns) {
    this.numHashColumns = numHashColumns;
  }

  public String getEncryptionAlgorithm() {
    return encryptionAlgorithm;
  }

  public void setEncryptionAlgorithm(String encryptionAlgorithm) {
    this.encryptionAlgorithm = encryptionAlgorithm;
  }

  public int getAesKeySize() {
    return aesKeySize;
  }

  public void setAesKeySize(int aesKeySize) {
    this.aesKeySize = aesKeySize;
  }

  public int getAesIvSize() {
    return aesIvSize;
  }

  public void setAesIvSize(int aesIvSize) {
    this.aesIvSize = aesIvSize;
  }

  public int getAesAadSize() {
    return aesAadSize;
  }

  public void setAesAadSize(int aesAadSize) {
    this.aesAadSize = aesAadSize;
  }
}
