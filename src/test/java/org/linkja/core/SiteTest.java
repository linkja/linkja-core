package org.linkja.saltengine;

import org.junit.jupiter.api.Test;
import org.linkja.core.FileHelper;
import org.mockito.Mockito;

import java.io.File;
import java.io.FileNotFoundException;

import static org.junit.jupiter.api.Assertions.*;

class SiteTest {
  @Test
  void constructor_Empty() {
    Site site = new Site();
    assertNull(site.getPublicKeyFile());
    assertNull(site.getSiteID());
    assertNull(site.getSiteName());
  }

  @Test
  void constructor_InvalidKeyFile() {
    FileHelper fileHelperMock = Mockito.mock(FileHelper.class);
    Mockito.when(fileHelperMock.exists(Mockito.any(File.class))).thenAnswer(invoke -> false);
    File file = new File("/test/path/assumed/invalid");
    assertThrows(FileNotFoundException.class, () -> new Site("1", "Test 1", file, fileHelperMock));
  }

  @Test
  void constructor_ValidKeyFile() throws FileNotFoundException {
    FileHelper fileHelperMock = Mockito.mock(FileHelper.class);
    Mockito.when(fileHelperMock.exists(Mockito.any(File.class))).thenAnswer(invoke -> true);
    File file = new File("/test/path/assumed/valid");
    Site site = new Site("1", "Test 1", file, fileHelperMock);
    assertEquals("1", site.getSiteID());
    assertEquals("Test 1", site.getSiteName());
    assertEquals(file.toURI(), site.getPublicKeyFile().toURI());
  }

  @Test
  void setSiteID_Trim() {
    Site site = new Site();
    site.setSiteID(" 1 2 ");
    assertEquals("1 2", site.getSiteID());

    site.setSiteID(null);
    assertNull(site.getSiteID());
  }

  @Test
  void setSiteName_Trim() {
    Site site = new Site();
    site.setSiteName(" Site Name ");
    assertEquals("Site Name", site.getSiteName());

    site.setSiteName(null);
    assertNull(site.getSiteName());
  }
}