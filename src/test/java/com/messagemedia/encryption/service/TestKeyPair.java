/*
 * Copyright (c) Message4U Pty Ltd 2014-2017
 *
 * Except as otherwise permitted by the Copyright Act 1967 (Cth) (as amended from time to time) and/or any other
 * applicable copyright legislation, the material may not be reproduced in any format and in any way whatsoever
 * without the prior written consent of the copyright owner.
 */

package com.messagemedia.encryption.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class TestKeyPair {
    private String publicKey;
    private String privateKey;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public static TestKeyPair createTestKeyPair(String cipherType) throws NoSuchAlgorithmException {
        KeyPair keyPair = KeyPairGenerator.getInstance(cipherType).generateKeyPair();

        TestKeyPair testKeyPair = new TestKeyPair();
        testKeyPair.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        testKeyPair.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        return testKeyPair;
    }
}
