/*
 * Copyright (c) Message4U Pty Ltd 2014-2017
 *
 * Except as otherwise permitted by the Copyright Act 1967 (Cth) (as amended from time to time) and/or any other
 * applicable copyright legislation, the material may not be reproduced in any format and in any way whatsoever
 * without the prior written consent of the copyright owner.
 */

package com.messagemedia.encryption.service;

import com.messagemedia.encryption.model.SignatureInfo;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Set;
import java.util.StringJoiner;

public class SignService {
    /**
     * Verify digital signature by comparing the data hashed and signed by MM
     * @param signatureInfo signature information
     * @return <code>true</code> if the signature is matched, <code>false</code> otherwise
     */
    public boolean verifySignature(SignatureInfo signatureInfo) {
        validateInputParameters(signatureInfo);

        //Verify signature
        try {
            String signAlgorithm = signatureInfo.getDigestType() + "with" + signatureInfo.getCipherType();
            Signature signature = Signature.getInstance(signAlgorithm);
            signature.initVerify(getPublicKey(signatureInfo.getPublicKey(), signatureInfo.getCipherType()));

            String messageToSign = signatureInfo.getRequestLine() + signatureInfo.getDate() + signatureInfo.getMessageContent();
            signature.update(messageToSign.getBytes());
            return signature.verify(Base64.getDecoder().decode(signatureInfo.getSignature()));
        } catch (Exception ex) {
            return false;
        }
    }

    private void validateInputParameters(SignatureInfo signatureInfo) {
        Set<ConstraintViolation<SignatureInfo>> violationSet = Validation.buildDefaultValidatorFactory().getValidator().validate(signatureInfo);
        if (violationSet.size() > 0) {
            StringJoiner violationJoiner = new StringJoiner("\n");
            for (ConstraintViolation<SignatureInfo> constraintViolation : violationSet) {
                violationJoiner.add(constraintViolation.getPropertyPath() + ": " + constraintViolation.getMessage());
            }
            throw new IllegalArgumentException("Signature info is invalid:\n" + violationJoiner.toString());
        }
    }

    private PublicKey getPublicKey(String keyString, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(spec);
    }
}
