package org.linkja.core;

import org.linkja.core.FileHelper;

import java.io.File;
import java.io.FileNotFoundException;

public class Site {
  private String siteID;
  private String siteName;

  public Site() {}

  public Site(String siteID, String siteName) throws FileNotFoundException {
      setSiteID(siteID);
      setSiteName(siteName);
  }

  public String getSiteID() {
    return siteID;
  }

  public void setSiteID(String siteID) {
    this.siteID = siteID;
    if (this.siteID != null) {
      this.siteID = this.siteID.trim();
    }
  }

  public String getSiteName() {
    return siteName;
  }

  public void setSiteName(String siteName) {
    this.siteName = siteName;
    if (this.siteName != null) {
      this.siteName = this.siteName.trim();
    }
  }
}
