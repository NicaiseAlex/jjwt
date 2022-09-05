package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.security.PrivateKey;

public class EdwardsCurveSigner extends EdwardsCurveProvider implements Signer {


    protected EdwardsCurveSigner(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        if (!(key instanceof PrivateKey)) {
            String msg = "Edwards Curve signatures must be computed using an ED PrivateKey. The specified key of " +
                    "type " + key.getClass().getName() + " is not an ED PrivateKey.";
            throw new io.jsonwebtoken.security.InvalidKeyException(msg);
        }
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
        return new byte[0];
    }
}
