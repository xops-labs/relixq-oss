// Intentionally vulnerable sample — DO NOT USE.
package com.example.legacy;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class LegacyCrypto {

    // MD5 — broken hash.
    public static byte[] digest(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(input);
    }

    // DES/ECB — broken cipher and insecure mode.
    public static Cipher legacyCipher(byte[] keyBytes) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }
}
