package org.linkja.core.crypto;

import org.linkja.crypto.Library;

import java.util.Arrays;

public class AesEncryptParameters {
  public static final String ALGORITHM_NAME = "AES-256";

  private byte[] key;
  private byte[] iv;
  private byte[] aad;

  public byte[] getKey() {
    return key;
  }

  public void setKey(byte[] key) {
    this.key = key;
  }

  public byte[] getIv() {
    return iv;
  }

  public void setIv(byte[] iv) {
    this.iv = iv;
  }

  public byte[] getAad() {
    return aad;
  }

  public void setAad(byte[] aad) {
    this.aad = aad;
  }

  public String getAlgorithmName() { return ALGORITHM_NAME; }

  public AesEncryptParameters(byte[] key, byte[] iv, byte[] aad) {
    this.key = key;
    this.iv = iv;
    this.aad = aad;
  }

  public static AesEncryptParameters generate(int keyLength, int ivLength, int aadLength) {
    AesEncryptParameters encryptParameters = new AesEncryptParameters(
      Library.generateKey(keyLength),
      Library.generateIV(ivLength),
      Library.generateKey(aadLength)
    );
    return encryptParameters;
  }

  /**
   * Clears the internal fields from memory
   */
  public void clear() {
    clearArray(key);
    key = null;
    clearArray(iv);
    iv = null;
    clearArray(aad);
    aad = null;
  }

  private void clearArray(byte[] array) {
    if (array != null) {
      Arrays.fill(array, (byte)0);
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    AesEncryptParameters that = (AesEncryptParameters) o;
    return Arrays.equals(key, that.key) &&
      Arrays.equals(iv, that.iv) &&
      Arrays.equals(aad, that.aad);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(key);
    result = 31 * result + Arrays.hashCode(iv);
    result = 31 * result + Arrays.hashCode(aad);
    return result;
  }
}
