package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.InvalidKeyException;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.ECKey;

public class EdwardsCurveProvider extends SignatureProvider {
    protected EdwardsCurveProvider(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(alg.isEdwardsCurve(), "SignatureAlgorithm must be an Elliptic Curve algorithm.");
        if (!(key instanceof EdDSAPrivateKey)) {
            String msg = "Edwards Curve signatures require an EdDSAPrivateKey. The provided key of type " +
                    key.getClass().getName() + " is not a " + EdDSAPrivateKey.class.getName() + " instance.";
            throw new InvalidKeyException(msg);
        }
        /* //TODO check si on peut l'adapter
        this.requiredSignatureByteLength = getSignatureByteArrayLength(alg);
        this.fieldByteLength = this.requiredSignatureByteLength / 2;

        EdDSAPrivateKey edDSAPrivateKey = (EdDSAPrivateKey) key; // can cast here because of the Assert.isTrue assertion above
        BigInteger order = ecKey.getParams().getOrder();
        int keyFieldByteLength = (order.bitLength() + 7) / Byte.SIZE; //for ES512 (can be 65 or 66, this ensures 66)
        int concatByteLength = keyFieldByteLength * 2;

        if (concatByteLength != this.requiredSignatureByteLength) {
            String msg = "EllipticCurve key has a field size of " +
                    byteSizeString(keyFieldByteLength) + ", but " + alg.name() + " requires a field size of " +
                    byteSizeString(this.fieldByteLength) + " per [RFC 7518, Section 3.4 (validation)]" +
                    "(https://datatracker.ietf.org/doc/html/rfc7518#section-3.4).";
            throw new InvalidKeyException(msg);
        }*/
    }
}
