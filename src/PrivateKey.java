import java.math.BigInteger;
import java.util.Arrays;
import java.security.SecureRandom;
import java.util.Base64;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

public class PrivateKey
{

    private Scalar scalar;
    private PublicKey pubKey;    

    public PrivateKey(Scalar sc, PublicKey pk)
    {
        scalar = sc;
        pubKey = pk;
    }

    public static PrivateKey generate(Curve curve)
    {
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        SecureRandom secureRandom = new SecureRandom();
        X9ECParameters secnamecurves = SECNamedCurves.getByName(curve.getName());
        ECDomainParameters ecParams = new ECDomainParameters(secnamecurves.getCurve(), secnamecurves.getG(), secnamecurves.getN(), secnamecurves.getH());
	ECKeyGenerationParameters keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
	gen.init(keyGenParam);
	AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        ECPrivateKeyParameters privatekey = (ECPrivateKeyParameters)kp.getPrivate();
        ECPublicKeyParameters publickey = (ECPublicKeyParameters)kp.getPublic();
        return new PrivateKey(new Scalar(privatekey.getD(), curve), new PublicKey(new GroupElement(curve, publickey.getQ())));
        
    }

    public Scalar getValue()
    {
        return scalar;
    }

    public PublicKey generatePublicKey()
    {
       Curve curve = new Curve("secp256k1");
       return new PublicKey(new GroupElement(curve, curve.getGenerator().multiply(scalar.getValue())));
    }
    public PublicKey getPublicKey()
    {
        return pubKey;
    }

    public static PrivateKey fromBytes(byte[] data)
    {
        return new PrivateKey(Scalar.fromBytes(data), null);
    }

    public byte[] toBytes()
    {
        return scalar.toBytes();
    }

}
