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

public class PublicKey
{

    private GroupElement pubKey;
    

    public PublicKey(GroupElement ge)
    {
        pubKey = ge;
    }

    public GroupElement getValue()
    {
        return pubKey;
    }

    public static PublicKey fromBytes(byte[] data)
    {
        return new PublicKey(GroupElement.fromBytes(data));
    }    
    public byte[] toBytes()
    {
        return pubKey.toBytes();
    }

}
