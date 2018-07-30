/*
 * Copyright (c) Message4U Pty Ltd 2014-2017
 *
 * Except as otherwise permitted by the Copyright Act 1967 (Cth) (as amended from time to time) and/or any other
 * applicable copyright legislation, the material may not be reproduced in any format and in any way whatsoever
 * without the prior written consent of the copyright owner.
 */

package com.messagemedia.encryption.model;

public final class SignatureInfoBuilder {
    private SignatureInfo signatureInfo;

    private SignatureInfoBuilder() {
        signatureInfo = new SignatureInfo();
    }

    public static SignatureInfoBuilder aSignatureInfo() {
        return new SignatureInfoBuilder();
    }

    public SignatureInfoBuilder withRequestLine(String requestLine) {
        signatureInfo.setRequestLine(requestLine);
        return this;
    }

    public SignatureInfoBuilder withDate(String date) {
        signatureInfo.setDate(date);
        return this;
    }

    public SignatureInfoBuilder withMessageContent(String messageContent) {
        signatureInfo.setMessageContent(messageContent);
        return this;
    }

    public SignatureInfoBuilder withDigestType(String digestType) {
        signatureInfo.setDigestType(digestType);
        return this;
    }

    public SignatureInfoBuilder withCipherType(String cipherType) {
        signatureInfo.setCipherType(cipherType);
        return this;
    }

    public SignatureInfoBuilder withPublicKey(String publicKey) {
        signatureInfo.setPublicKey(publicKey);
        return this;
    }

    public SignatureInfoBuilder withSignature(String signature) {
        signatureInfo.setSignature(signature);
        return this;
    }

    public SignatureInfo build() {
        return signatureInfo;
    }
}
