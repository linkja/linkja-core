package org.linkja.saltengine;

import org.linkja.core.FileHelper;

import java.io.File;
import java.io.FileNotFoundException;

public class Site {
  private String siteID;
  private String siteName;
  private File publicKeyFile;
  private FileHelper fileHelper;

  public Site() {
    this.fileHelper = new FileHelper();
  }

  public Site(String siteID, String siteName, File publicKeyFile) throws FileNotFoundException {
    initialize(siteID, siteName, publicKeyFile, new FileHelper());
  }

  public Site(String siteID, String siteName, File publicKeyFile, FileHelper fileHelper) throws FileNotFoundException {
    initialize(siteID, siteName, publicKeyFile, fileHelper);
  }

  private void initialize(String siteID, String siteName, File publicKeyFile, FileHelper fileHelper) throws FileNotFoundException {
    this.fileHelper = fileHelper;
    setSiteID(siteID);
    setSiteName(siteName);
    setPublicKeyFile(publicKeyFile);
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

  public File getPublicKeyFile() {
    return publicKeyFile;
  }

  public void setPublicKeyFile(File publicKeyFile) throws FileNotFoundException {
    if (!fileHelper.exists(publicKeyFile)) {
      throw new FileNotFoundException("The public key file could not be found at the location specified");
    }
    this.publicKeyFile = publicKeyFile;
  }
}
