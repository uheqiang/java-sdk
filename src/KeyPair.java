import java.math.BigInteger;
import java.util.Arrays;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

public class KeyPair
{
    private PrivateKey privateKey;
    private PublicKey publicKey;
    

    public KeyPair(PrivateKey sk, PublicKey pk)
    {
        privateKey = sk;
        publicKey = pk;
    }


    public static KeyPair generateKeyPair()
    {
        PrivateKey privateKey = PrivateKey.generate(new Curve("secp256k1"));
        return new KeyPair(privateKey, privateKey.getPublicKey());
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }
    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }


}
