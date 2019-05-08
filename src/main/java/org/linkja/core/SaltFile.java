package org.linkja.core;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class SaltFile {
  public final static String SALT_FILE_DELIMITER = ",";

  public final static int NUM_SALT_PARTS = 5;

  /**
   * This is the absolute minimum that we will allow to be specified for the salt length file.  This is enforced
   * to protect privacy of the data, since validation was done on a minimum salt length of 13.
   */
  public final static int ABS_MIN_SALT_LENGTH = 13;

  private String siteId;
  private String siteName;
  private String privateSalt;
  private String projectSalt;
  private String projectName;
  private int minSaltLength;

  public String getSiteId() {
    return siteId;
  }

  public void setSiteId(String siteId) {
    this.siteId = siteId;
  }

  public String getSiteName() {
    return siteName;
  }

  public void setSiteName(String siteName) {
    this.siteName = siteName;
  }

  public String getPrivateSalt() {
    return privateSalt;
  }

  public void setPrivateSalt(String privateSalt) {
    this.privateSalt = privateSalt;
  }

  public String getProjectSalt() {
    return projectSalt;
  }

  public void setProjectSalt(String projectSalt) {
    this.projectSalt = projectSalt;
  }

  public String getProjectName() {
    return projectName;
  }

  public void setProjectName(String projectName) {
    this.projectName = projectName;
  }

  public int getMinSaltLength() {
    return minSaltLength;
  }

  public void setMinSaltLength(int minSaltLength) throws LinkjaException {
    if (minSaltLength < ABS_MIN_SALT_LENGTH) {
      throw new LinkjaException(String.format("The project salt's minimum length cannot be less than %d characters", ABS_MIN_SALT_LENGTH));
    }
    this.minSaltLength = minSaltLength;
  }

  public SaltFile() { this.minSaltLength = ABS_MIN_SALT_LENGTH; }

  /**
   * Loads an encrypted salt file and populates this object with the appropriate values
   * @param saltFile
   * @param privateKey
   * @throws Exception
   */
  public void decrypt(File saltFile, File privateKey) throws Exception {
    if (saltFile == null || privateKey == null) {
      throw new LinkjaException("You must specify the encrypted salt file as well as the private key");
    }

    CryptoHelper helper = new CryptoHelper();
    String decryptedMessage = new String(helper.decryptRSA(saltFile, privateKey), StandardCharsets.UTF_8);
    String[] saltParts = decryptedMessage.split(SALT_FILE_DELIMITER);
    if (saltParts == null || saltParts.length < NUM_SALT_PARTS) {
      throw new LinkjaException("The salt file was not in the expected format.  Please confirm that you are referencing the correct file");
    }

    // At this point we have to assume that everything is in the right position, so we will load by position.
    setSiteId(saltParts[0]);
    setSiteName(saltParts[1]);
    setPrivateSalt(saltParts[2]);
    setProjectSalt(saltParts[3]);
    setProjectName(saltParts[4]);

    if (this.projectSalt.length() < minSaltLength) {
      throw new LinkjaException(String.format("The project salt must be at least %d characters long, but the one provided is %d",
              minSaltLength, this.projectSalt.length()));
    }
    if (this.privateSalt.length() < minSaltLength) {
      throw new LinkjaException(String.format("The private (site-specific) salt must be at least %d characters long, but the one provided is %d",
              minSaltLength, this.privateSalt.length()));
    }
  }

  /**
   * Takes the current salt file fields and creates an encrypted version of the salt file using the supplied
   * RSA public key
   * @param saltFile
   * @param publicKey
   * @throws Exception
   */
  public void encrypt(File saltFile, File publicKey) throws Exception {
    if (saltFile == null || publicKey == null) {
      throw new LinkjaException("You must specify a file to write to, and the public to to use for encryption");
    }

    CryptoHelper helper = new CryptoHelper();
    String hashFileContent = String.format("%s,%s,%s,%s,%s",
            getSiteId(), getSiteName(), getPrivateSalt(), getProjectSalt(), getProjectName());
    Files.write(saltFile.toPath(), helper.encryptRSA(hashFileContent.getBytes(), publicKey));
  }

  /**
   * Helper function to generate a valid salt file name (removing invalid characters), given a project name
   * and a site ID
   * @param project
   * @param siteID
   * @return
   * @throws LinkjaException
   */
  public String getSaltFileName(String project, String siteID) throws LinkjaException {
    if (siteID == null || siteID.equals("")) {
      throw new LinkjaException("The site ID cannot be empty");
    }
    if (project == null || project.equals("")) {
      throw new LinkjaException("The project name cannot be empty");
    }

    String fileName = String.format("%s_%s_%s.txt", project.replaceAll("[^\\w]", ""),
            siteID.replaceAll("[^\\w]", ""),
            LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd")));
    return fileName;
  }
}
