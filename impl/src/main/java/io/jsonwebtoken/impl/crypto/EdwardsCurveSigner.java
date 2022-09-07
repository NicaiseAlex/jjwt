package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import java.security.*;

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
        try {
            //TODO io.jsonwebtoken.security.SignatureException: Invalid Elliptic Curve PrivateKey. No installed provider supports this key: net.i2p.crypto.eddsa.EdDSAPrivateKey
            Security.addProvider(new EdDSASecurityProvider());
            return doSign(data);
        } catch (InvalidKeyException e) {
            throw new SignatureException("Invalid Elliptic Curve PrivateKey. " + e.getMessage(), e);
        } catch (java.security.SignatureException e) {
            throw new SignatureException("Unable to calculate signature using Elliptic Curve PrivateKey. " + e.getMessage(), e);
        } catch (JwtException e) {
            throw new SignatureException("Unable to convert signature to JOSE format. " + e.getMessage(), e);
        }
    }

    protected byte[] doSign(byte[] data) throws InvalidKeyException, java.security.SignatureException, JwtException {
        PrivateKey privateKey = (PrivateKey)key;
        Signature sig = createSignatureInstance();
        sig.initSign(privateKey);
        sig.update(data);
        return transcodeDERToConcat(sig.sign(), getSignatureByteArrayLength(alg));
    }
}
