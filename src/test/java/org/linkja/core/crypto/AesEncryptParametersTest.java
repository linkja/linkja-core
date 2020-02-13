package org.linkja.core.crypto;

import org.junit.jupiter.api.Test;
import org.linkja.core.LinkjaException;

import static org.junit.jupiter.api.Assertions.*;

class AesEncryptParametersTest {

    @Test
    void generate_invalidLengths() {
      assertNull(AesEncryptParameters.generate(-1, 32, 32).getKey());
      assertNull(AesEncryptParameters.generate(32, -1, 32).getIv());
      assertNull(AesEncryptParameters.generate(32, 32, -1).getAad());
    }

    @Test
    void generate() {
      // Generate two parameters of the same length for each field - each should be different because they
      // are randomly filled.
      AesEncryptParameters params1 = AesEncryptParameters.generate(32, 32, 32);
      AesEncryptParameters params2 = AesEncryptParameters.generate(32, 32, 32);
      assertNotEquals(params1, params2);
    }

    @Test
    void clear_empty() {
      AesEncryptParameters params = AesEncryptParameters.generate(0, 0, 0);
      assertDoesNotThrow(() -> params.clear());
      assertDoesNotThrow(() -> params.clear());
    }

    @Test
    void clear() {
      AesEncryptParameters params = AesEncryptParameters.generate(32, 32, 32);
      assertNotNull(params.getKey());
      assertNotNull(params.getIv());
      assertNotNull(params.getAad());

      params.clear();
      assertNull(params.getKey());
      assertNull(params.getIv());
      assertNull(params.getAad());
    }

  @Test
  void testClone() {
    AesEncryptParameters params = AesEncryptParameters.generate(32, 16, 64);
    AesEncryptParameters clonedParams = params.clone();

    // The pointers should be different...
    assertFalse(clonedParams == params);
    assertFalse(clonedParams.getKey() == params.getKey());
    assertFalse(clonedParams.getIv() == params.getIv());
    assertFalse(clonedParams.getAad() == params.getAad());

    // ...but the values should be the same
    assertEquals(clonedParams, params);
  }

  @Test
  void testClone_clear() {
    AesEncryptParameters params = AesEncryptParameters.generate(32, 16, 64);
    AesEncryptParameters clonedParams = params.clone();
    params.clear();

    // The pointers should be different...
    assertNotNull(clonedParams.getKey());
    assertNotNull(clonedParams.getIv());
    assertNotNull(clonedParams.getAad());
  }
}
