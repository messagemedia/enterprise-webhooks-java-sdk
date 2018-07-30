/*
 * Copyright (c) Message4U Pty Ltd 2014-2017
 *
 * Except as otherwise permitted by the Copyright Act 1967 (Cth) (as amended from time to time) and/or any other
 * applicable copyright legislation, the material may not be reproduced in any format and in any way whatsoever
 * without the prior written consent of the copyright owner.
 */

package com.messagemedia.encryption.service;

import com.messagemedia.encryption.model.SignatureInfo;
import com.messagemedia.encryption.model.SignatureInfoBuilder;
import com.tngtech.java.junit.dataprovider.DataProvider;
import com.tngtech.java.junit.dataprovider.DataProviderRunner;
import com.tngtech.java.junit.dataprovider.UseDataProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@RunWith(DataProviderRunner.class)
public class SignServiceTest {
    private SignService signService;

    @Before
    public void setup() {
        signService = new SignService();
    }

    @DataProvider
    public static Object[][] signatureData() {
        return new Object[][] {
                {"SHA224", "RSA", "GET /test1/moreceiver HTTP/1.1", "Fri, 08 Dec 2017 09:30:00 GMT", "Message 1"},
                {"SHA256", "RSA", "POST /test2/drreceiver HTTP/1.1", "Wed, 29 Nov 2017 13:59:00 GMT", "Message 2"},
                {"SHA512", "RSA", "PATCH /test3/receivers HTTP/1.1", "Tue, 10 Oct 2017 21:18:00 GMT", "Message 3"}
        };
    }

    @Test
    @UseDataProvider("signatureData")
    public void shouldVerifySignatureSuccess(String digestType, String cipherType, String requestLine, String date, String messageContent)
        throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        TestKeyPair testKeyPair = TestKeyPair.createTestKeyPair(cipherType);
        String messageToSign = getMessageToSign(requestLine, date, messageContent);
        String signAlgorithm = getSignAlgorithm(digestType, cipherType);
        String testSignature = createTestSignature(signAlgorithm, cipherType, testKeyPair.getPrivateKey(), messageToSign);

        SignatureInfo testSignatureInfo = SignatureInfoBuilder
                .aSignatureInfo()
                .withRequestLine(requestLine)
                .withDate(date)
                .withMessageContent(messageContent)
                .withDigestType(digestType)
                .withCipherType(cipherType)
                .withPublicKey(testKeyPair.getPublicKey())
                .withSignature(testSignature)
                .build();
        Assert.assertTrue(signService.verifySignature(testSignatureInfo));
    }

    @Test
    @UseDataProvider("signatureData")
    public void shouldVerifySignatureFailWhenWrongMessageToSign(String digestType, String cipherType, String requestLine, String date,
        String messageContent) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        TestKeyPair testKeyPair = TestKeyPair.createTestKeyPair(cipherType);
        String messageToSign = getMessageToSign(requestLine, date, messageContent);
        String signAlgorithm = getSignAlgorithm(digestType, cipherType);
        String testSignature = createTestSignature(signAlgorithm, cipherType, testKeyPair.getPrivateKey(), messageToSign);

        SignatureInfo testSignatureInfo = SignatureInfoBuilder
                .aSignatureInfo()
                .withRequestLine(requestLine)
                .withDate(date)
                .withMessageContent(messageContent + "abc")
                .withDigestType(digestType)
                .withCipherType(cipherType)
                .withPublicKey(testKeyPair.getPublicKey())
                .withSignature(testSignature)
                .build();
        Assert.assertFalse(signService.verifySignature(testSignatureInfo));
    }

    @Test
    @UseDataProvider("signatureData")
    public void shouldVerifySignatureFailWhenDifferentKey(String digestType, String cipherType, String requestLine, String date,
        String messageContent) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        TestKeyPair testKeyPair = TestKeyPair.createTestKeyPair(cipherType);
        TestKeyPair anotherKeyPair = TestKeyPair.createTestKeyPair(cipherType);
        String messageToSign = getMessageToSign(requestLine, date, messageContent);
        String signAlgorithm = getSignAlgorithm(digestType, cipherType);
        String testSignature = createTestSignature(signAlgorithm, cipherType, testKeyPair.getPrivateKey(), messageToSign);

        SignatureInfo testSignatureInfo = SignatureInfoBuilder
                .aSignatureInfo()
                .withRequestLine(requestLine)
                .withDate(date)
                .withMessageContent(messageContent)
                .withDigestType(digestType)
                .withCipherType(cipherType)
                .withPublicKey(anotherKeyPair.getPublicKey())
                .withSignature(testSignature)
                .build();
        Assert.assertFalse(signService.verifySignature(testSignatureInfo));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionWhenSignatureInfoIsNull() {
        signService.verifySignature(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionWhenInputParameterIsBlankOrNull() {
        SignatureInfo signatureInfo = SignatureInfoBuilder
                .aSignatureInfo()
                .withRequestLine("")
                .withDate("")
                .withDigestType("")
                .withCipherType("")
                .withPublicKey("")
                .withSignature("")
                .build();
        signService.verifySignature(signatureInfo);
    }

    private String createTestSignature(String signAlgorithm, String cipherType, String privateKey, String messageToSign)
        throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(signAlgorithm);
        signature.initSign(getPrivateKey(privateKey, cipherType));
        signature.update(messageToSign.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private PrivateKey getPrivateKey(String keyString, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyString));
        return KeyFactory.getInstance(algorithm).generatePrivate(encodedKeySpec);
    }

    private String getSignAlgorithm(String digestType, String cipherType) {
        return digestType.trim() + "with" + cipherType.trim();
    }

    private String getMessageToSign(String requestLine, String date, String messageContent) {
        return requestLine + date + messageContent;
    }
}
