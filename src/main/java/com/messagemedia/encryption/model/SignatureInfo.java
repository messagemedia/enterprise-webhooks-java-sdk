/*
 * Copyright (c) Message4U Pty Ltd 2014-2017
 *
 * Except as otherwise permitted by the Copyright Act 1967 (Cth) (as amended from time to time) and/or any other
 * applicable copyright legislation, the material may not be reproduced in any format and in any way whatsoever
 * without the prior written consent of the copyright owner.
 */

package com.messagemedia.encryption.model;

import org.apache.commons.lang3.builder.ToStringBuilder;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.Objects;

public class SignatureInfo {
    /**
     * Http request line to calculate the signature
     */
    @NotBlank
    private String requestLine;
    /**
     * Date in http header to calculate the signature
     */
    @NotBlank
    private String date;
    /**
     * Message content to calculate the signature
     */
    @NotNull
    private String messageContent;
    /**
     * Digest type to hash requestLine + date + messageContent
     */
    @NotBlank
    private String digestType;
    /**
     * Cipher type to encrypt the hashed message
     */
    @NotBlank
    private String cipherType;
    /**
     * Public key to decrypt the signature
     */
    @NotBlank
    private String publicKey;
    /**
     * Signature sent by MM in http header
     */
    @NotBlank
    private String signature;

    public String getRequestLine() {
        return requestLine;
    }

    public void setRequestLine(String requestLine) {
        this.requestLine = requestLine;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public String getMessageContent() {
        return messageContent;
    }

    public void setMessageContent(String messageContent) {
        this.messageContent = messageContent;
    }

    public String getDigestType() {
        return digestType;
    }

    public void setDigestType(String digestType) {
        this.digestType = digestType;
    }

    public String getCipherType() {
        return cipherType;
    }

    public void setCipherType(String cipherType) {
        this.cipherType = cipherType;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SignatureInfo)) {
            return false;
        }
        SignatureInfo that = (SignatureInfo) o;
        return Objects.equals(requestLine, that.requestLine)
                && Objects.equals(date, that.date)
                && Objects.equals(messageContent, that.messageContent)
                && Objects.equals(digestType, that.digestType)
                && Objects.equals(cipherType, that.cipherType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(requestLine, date, messageContent, digestType, cipherType);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("requestLine", requestLine)
                .append("date", date)
                .append("messageContent", messageContent)
                .append("digestType", digestType)
                .append("cipherType", cipherType)
                .append("publicKey", publicKey)
                .append("signature", signature)
                .toString();
    }
}
