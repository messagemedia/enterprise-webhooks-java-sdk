/*
 * Copyright (c) Message4U Pty Ltd 2014-2017
 *
 * Except as otherwise permitted by the Copyright Act 1967 (Cth) (as amended from time to time) and/or any other
 * applicable copyright legislation, the material may not be reproduced in any format and in any way whatsoever
 * without the prior written consent of the copyright owner.
 */

package com.messagemedia.encryption.model;

import org.junit.Test;

import java.util.UUID;

import static com.messagemedia.framework.test.AccessorAsserter.assertGettersAndSetters;
import static com.messagemedia.framework.test.CanonicalAsserter.assertCanonical;
import static com.messagemedia.framework.test.CanonicalAsserter.assertToString;

public class SignatureInfoTest {
    @Test
    public void shouldHaveGettersAndSetters() throws Exception {
        assertGettersAndSetters(randomSignatureInfo());
    }

    @Test
    public void testToString() {
        assertToString(randomSignatureInfo());
    }

    @Test
    public void testCanonical() {
        SignatureInfo signatureInfo = randomSignatureInfo();
        SignatureInfo duplicateSignatureInfo = randomSignatureInfo();
        duplicateSignatureInfo.setRequestLine(signatureInfo.getRequestLine());
        duplicateSignatureInfo.setDate(signatureInfo.getDate());
        duplicateSignatureInfo.setMessageContent(signatureInfo.getMessageContent());
        duplicateSignatureInfo.setDigestType(signatureInfo.getDigestType());
        duplicateSignatureInfo.setCipherType(signatureInfo.getCipherType());
        SignatureInfo differentSignatureInfo = randomSignatureInfo();
        assertCanonical(signatureInfo, duplicateSignatureInfo, differentSignatureInfo);
    }

    private SignatureInfo randomSignatureInfo() {
        return SignatureInfoBuilder
                .aSignatureInfo()
                .withRequestLine("POST /" + UUID.randomUUID() + " HTTP/1.1")
                .withDate("Fri, 08 Dec 2017 09:30:00 GMT")
                .withMessageContent("{\"any\":\"" + UUID.randomUUID() + "\"}")
                .withDigestType("SHA512")
                .withCipherType("RSA")
                .withPublicKey("ANY_PUBLIC_KEY_" + UUID.randomUUID())
                .withSignature("ANY_SIGNATURE_" + UUID.randomUUID())
                .build();
    }
}
