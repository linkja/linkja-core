package org.linkja.core;

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
    assertNull(site.getSiteID());
    assertNull(site.getSiteName());
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
