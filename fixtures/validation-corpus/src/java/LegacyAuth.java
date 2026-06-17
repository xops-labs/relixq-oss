package com.example.auth;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

public class LegacyAuth {

    public KeyPairGenerator rsaGenerator() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg;
    }

    public Signature ecdsaSigner() throws Exception {
        return Signature.getInstance("SHA256withECDSA");
    }

    public KeyAgreement dhAgreement() throws Exception {
        return KeyAgreement.getInstance("DiffieHellman");
    }

    public Cipher tripleDesCipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    public Cipher rc4Cipher() throws Exception {
        return Cipher.getInstance("RC4");
    }

    public MessageDigest sha1Digest() throws Exception {
        return MessageDigest.getInstance("SHA-1");
    }
}
