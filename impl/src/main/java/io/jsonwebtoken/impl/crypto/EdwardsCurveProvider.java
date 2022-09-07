package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SignatureException;
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

    public static byte[] transcodeDERToConcat(final byte[] derSignature, int outputLength) throws JwtException {

        if (derSignature.length < 8 || derSignature[0] != 48) {
            throw new JwtException("Invalid ECDSA signature format");
        }

        int offset;
        if (derSignature[1] > 0) {
            offset = 2;
        } else if (derSignature[1] == (byte) 0x81) {
            offset = 3;
        } else {
            throw new JwtException("Invalid ECDSA signature format");
        }

        byte rLength = derSignature[offset + 1];

        int i = rLength;
        while ((i > 0) && (derSignature[(offset + 2 + rLength) - i] == 0)) {
            i--;
        }

        byte sLength = derSignature[offset + 2 + rLength + 1];

        int j = sLength;
        while ((j > 0) && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0)) {
            j--;
        }

        int rawLen = Math.max(i, j);
        rawLen = Math.max(rawLen, outputLength / 2);

        if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset
                || (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || derSignature[offset] != 2
                || derSignature[offset + 2 + rLength] != 2) {
            throw new JwtException("Invalid ECDSA signature format");
        }

        final byte[] concatSignature = new byte[2 * rawLen];

        System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i);
        System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j);

        return concatSignature;
    }


    /**
     * Transcodes the ECDSA JWS signature into ASN.1/DER format for use by
     * the JCA verifier.
     *
     * @param jwsSignature The JWS signature, consisting of the
     *                     concatenated R and S values. Must not be
     *                     {@code null}.
     * @return The ASN.1/DER encoded signature.
     * @throws JwtException If the ECDSA JWS signature format is invalid.
     */
    public static byte[] transcodeConcatToDER(byte[] jwsSignature) throws JwtException {
        try {
            return concatToDER(jwsSignature);
        } catch (Exception e) { // CVE-2022-21449 guard
            String msg = "Invalid ECDSA signature format.";
            throw new SignatureException(msg, e);
        }
    }

    private static byte[] concatToDER(byte[] jwsSignature) throws ArrayIndexOutOfBoundsException {

        int rawLen = jwsSignature.length / 2;

        int i = rawLen;

        while ((i > 0) && (jwsSignature[rawLen - i] == 0)) {
            i--;
        }

        int j = i;

        if (jwsSignature[rawLen - i] < 0) {
            j += 1;
        }

        int k = rawLen;

        while ((k > 0) && (jwsSignature[2 * rawLen - k] == 0)) {
            k--;
        }

        int l = k;

        if (jwsSignature[2 * rawLen - k] < 0) {
            l += 1;
        }

        int len = 2 + j + 2 + l;

        if (len > 255) {
            throw new JwtException("Invalid ECDSA signature format");
        }

        int offset;

        final byte[] derSignature;

        if (len < 128) {
            derSignature = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        } else {
            derSignature = new byte[3 + 2 + j + 2 + l];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        }

        derSignature[0] = 48;
        derSignature[offset++] = (byte) len;
        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) j;

        System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

        offset += j;

        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) l;

        System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

        return derSignature;
    }

    public static int getSignatureByteArrayLength(final SignatureAlgorithm alg) throws JwtException {
        switch (alg) {
            case ED25519:
                return 64;
            default:
                throw new JwtException("Unsupported Algorithm: " + alg.name());
        }
    }
}
