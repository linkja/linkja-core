package org.linkja.core;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileHelper {
  public Path createDirectory(String directoryName) throws IOException {
    return Files.createDirectory(Paths.get(directoryName));
  }

  public boolean exists(File file) {
    return file.exists();
  }

  public boolean exists(Path path) {
    return Files.exists(path);
  }

  public Path pathFromString(String path) {
    return Paths.get(path);
  }


  /**
   * Writes the 32-bit int to the binary output stream.
   * @param x the {@code int} to write
   */
  public static void writeInt(BufferedOutputStream stream, int x) throws IOException {
    for (int index = Integer.BYTES - 1; index >= 0; index--) {
      stream.write((byte)((x >>> (8 * index)) & 0xFF));
    }
  }

  /**
   * Writes the 64-bit long to the binary output stream.
   * @param x the {@code long} to write
   */
  public static void writeLong(BufferedOutputStream stream, long x) throws IOException {
    for (int index = Long.BYTES - 1; index >= 0; index--) {
      stream.write((byte)((x >>> (8 * index)) & 0xFF));
    }
  }

  /**
   * Writes the 64-bit long to the binary output stream.
   * @param x the {@code long} to write
   */
  public static void writeLong(RandomAccessFile file, long x) throws IOException {
    for (int index = Long.BYTES - 1; index >= 0; index--) {
      file.write((byte)((x >>> (8 * index)) & 0xFF));
    }
  }


  /**
   * Reads the 32-bit int from the binary input stream.
   * @param stream the {@code BufferedInputStream} to read from
   * @param exceptionMessage a descriptive exception message to throw if reading fails
   * @return the 32-bit int
   * @throws LinkjaException
   * @throws IOException
   */
  public static int readInt(BufferedInputStream stream, String exceptionMessage) throws LinkjaException, IOException {
    byte[] buffer = new byte[Integer.BYTES];
    int result = stream.read(buffer, 0, Integer.BYTES);
    if (result != Integer.BYTES) {
      throw new LinkjaException(exceptionMessage);
    }

    int value = ByteBuffer.wrap(buffer, 0, Integer.BYTES).getInt();
    return value;
  }

  /**
   * Reads the 64-bit long from the binary input stream.
   * @param stream the {@code BufferedInputStream} to read from
   * @param exceptionMessage a descriptive exception message to throw if reading fails
   * @return the 64-bit long
   * @throws LinkjaException
   * @throws IOException
   */
  public static long readLong(BufferedInputStream stream, String exceptionMessage) throws LinkjaException, IOException {
    byte[] buffer = new byte[Long.BYTES];

    int result = stream.read(buffer, 0, Long.BYTES);
    if (result != Long.BYTES) {
      throw new LinkjaException(exceptionMessage);
    }

    long value = ByteBuffer.wrap(buffer, 0, Long.BYTES).getLong();
    return value;
  }
}
