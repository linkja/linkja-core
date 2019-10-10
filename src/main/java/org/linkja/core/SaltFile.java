package org.linkja.core;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class SaltFile {
  public final static String SALT_FILE_DELIMITER = ",";

  public final static int NUM_SALT_PARTS = 5;

  /**
   * This is the absolute minimum that we will allow to be specified for the salt length file.  This is enforced
   * to protect privacy of the data, since validation was done on a minimum salt length of 13.
   */
  public final static int ABS_MIN_SALT_LENGTH = 13;

  private Site site;
  private String privateSalt;
  private String projectSalt;
  private String projectName;
  private int minSaltLength;

  public String getSiteID() {
    return site.getSiteID();
  }

  public String getSiteName() {
    return site.getSiteName();
  }

  public void setSite(Site site) {
    this.site = site;
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

  public SaltFile() {
    this.minSaltLength = ABS_MIN_SALT_LENGTH;
    this.site = new Site();
  }

  /**
   * Loads a plain (unencrypted) salt file and populates this object with the appropriate values
   * @param saltFile
   * @throws Exception
   */
  public void load(File saltFile) throws Exception {
    if (saltFile == null) {
      throw new LinkjaException("You must specify the salt file to load");
    }

    List<String> saltMessage = Files.readAllLines(saltFile.toPath());
    if (saltMessage == null || saltMessage.size() != 1) {
      throw new LinkjaException("The salt file must contain exactly one line");
    }

    String[] saltParts = saltMessage.get(0).split(SALT_FILE_DELIMITER);
    loadFromParts(saltParts);
  }

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
    loadFromParts(saltParts);
  }

  public void loadFromParts(String[] parts) throws LinkjaException {
    if (parts == null || parts.length < NUM_SALT_PARTS) {
      throw new LinkjaException("The salt file was not in the expected format.  Please confirm that you are referencing the correct file");
    }

    // At this point we have to assume that everything is in the right position, so we will load by position.
    site.setSiteID(parts[0]);
    site.setSiteName(parts[1]);
    setPrivateSalt(parts[2]);
    setProjectSalt(parts[3]);
    setProjectName(parts[4]);

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

    if (this.site == null) {
      throw new LinkjaException("Please specify the site information in order to create the salt file");
    }

    CryptoHelper helper = new CryptoHelper();
    String hashFileContent = String.format("%s,%s,%s,%s,%s",
            getSiteID(), getSiteName(), getPrivateSalt(), getProjectSalt(), getProjectName());
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
