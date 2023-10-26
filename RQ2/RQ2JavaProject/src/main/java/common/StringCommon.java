package common;

import org.bouncycastle.util.encoders.Hex;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;

public class StringCommon {

    public static boolean isContainBOM(Path path) throws IOException {

        if (Files.notExists(path)) {
            throw new IllegalArgumentException("Path: " + path + " does not exists!");
        }

        boolean result = false;

        byte[] bom = new byte[3];
        try (InputStream is = new FileInputStream(path.toFile())) {

            // read 3 bytes of a file.
            is.read(bom);

            // BOM encoded as ef bb bf
            String content = new String(Hex.encode(bom));
            if ("efbbbf".equalsIgnoreCase(content)) {
                result = true;
            }
        }
        return result;
    }



    public static void removeBom(Path path) throws IOException {

        if (isContainBOM(path)) {

            byte[] bytes = Files.readAllBytes(path);

            ByteBuffer bb = ByteBuffer.wrap(bytes);

            System.out.println("Found BOM!");

            byte[] bom = new byte[3];
            // get the first 3 bytes
            bb.get(bom, 0, bom.length);

            // remaining
            byte[] contentAfterFirst3Bytes = new byte[bytes.length - 3];
            bb.get(contentAfterFirst3Bytes, 0, contentAfterFirst3Bytes.length);

            System.out.println("Remove the first 3 bytes, and overwrite the file!");

            // override the same path
            Files.write(path, contentAfterFirst3Bytes);

        } else {
            System.out.println("This file doesn't contains UTF-8 BOM!");
        }

    }
}
