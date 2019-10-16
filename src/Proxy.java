import java.math.BigInteger;
import java.util.Arrays;
import java.security.SecureRandom;
import java.util.List;
import java.security.NoSuchAlgorithmException;

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

public class Proxy
{

    public static KeyPair generateKeyPair()
    {
        return KeyPair.generateKeyPair();
    }

    public static List<Object> encapsulate(PublicKey publicKey) throws NoSuchAlgorithmException
    {

        KeyPair kp1 = Proxy.generateKeyPair();
        KeyPair kp2 = Proxy.generateKeyPair();

        Scalar sk1 = kp1.getPrivateKey().getValue();
        Scalar sk2 = kp2.getPrivateKey().getValue();

        GroupElement pk1 = kp1.getPublicKey().getValue();
        GroupElement pk2 = kp2.getPublicKey().getValue();

        GroupElement[] tmpHash = {pk1, pk2};
        Scalar hash = ProxyUtils.hashToScalar(tmpHash);

        Scalar partS = sk1.add(sk2.mul(hash));  
        GroupElement pkPoint = publicKey.getValue();

        GroupElement pointSymmetric = pkPoint.mul(sk1.add(sk2));
        Scalar symmetricKey = ProxyUtils.SHA256(pointSymmetric);
      
        Capsule capsule = new Capsule(pk1, pk2, partS, null, false);

        return Arrays.asList(capsule, symmetricKey);
    }

    public static Scalar decapsulateOriginal(Capsule capsule, PrivateKey privateKey) throws NoSuchAlgorithmException
    {
        Scalar sk = privateKey.getValue();
        GroupElement s = capsule.getE().add(capsule.getV());
        GroupElement pointSymmetric = s.mul(sk);
        Scalar symmetricKey = ProxyUtils.SHA256(pointSymmetric);
        return symmetricKey;
    }
    
    public static ReEncryptionKey generateReEncryptionKey(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException
    {
        KeyPair kp = KeyPair.generateKeyPair();

        Scalar tmpSk = kp.getPrivateKey().getValue();
        GroupElement tmpPk = kp.getPublicKey().getValue();
        
        GroupElement pkPoint = publicKey.getValue();

        GroupElement[] pointsForHash = {tmpPk, pkPoint, pkPoint.mul(tmpSk)};

        Scalar hash = ProxyUtils.hashToScalar(pointsForHash);

        Scalar sk = privateKey.getValue();
        Scalar hashInv = hash.invm();
        Scalar rk = sk.mul(hashInv);
        return new ReEncryptionKey(rk, tmpPk);

    }

    public static Capsule reEncryptCapsule(Capsule capsule, ReEncryptionKey rk) throws NoSuchAlgorithmException
    {

        GroupElement primeE = capsule.getE().mul(rk.getReKey());
        GroupElement primeV = capsule.getV().mul(rk.getReKey());
        Scalar primeS = capsule.getS();

        return new Capsule(primeE, primeV, primeS, rk.getInternalPublicKey(), true);  // Is_reencrypted = true
    }

    
    public static Scalar decapsulateReEncrypted(Capsule capsule, PrivateKey privateKey) throws NoSuchAlgorithmException
    {
        GroupElement primeXG = capsule.getXG();
        GroupElement primeE = capsule.getE();
        GroupElement primeV = capsule.getV();

        // concat prime_XG, publicKey point, prime_XG * sk 
        GroupElement[] pointsForHash = {primeXG, privateKey.getPublicKey().getValue(), primeXG.mul(privateKey.getValue())};
        Scalar hash = ProxyUtils.hashToScalar(pointsForHash);

        // (capsule.E + capsule.V) * hash_bn
        GroupElement tmpKdfPoint = primeE.add(primeV).mul(hash);

        Scalar symmetricKey = ProxyUtils.SHA256(tmpKdfPoint);
        return symmetricKey;
    }
    
    public static Scalar decapsulate(Capsule capsule, PrivateKey privateKey) throws NoSuchAlgorithmException
    {
        if(capsule.getIsReEncrypted())
        {
            return Proxy.decapsulateReEncrypted(capsule, privateKey);
        }
        return Proxy.decapsulateOriginal(capsule, privateKey);

    } 

    public static PrivateKey privateKeyFromBytes(byte[] data)
    {
        return PrivateKey.fromBytes(data);
    }

    public static PublicKey publicKeyFromBytes(byte[] data)
    {
        return PublicKey.fromBytes(data);
    }

    public static ReEncryptionKey reEncryptionKeyFromBytes(byte[] data)
    {
        return ReEncryptionKey.fromBytes(data);
    }

    public static Capsule capsuleFromBytes(byte[] data)
    {
        return Capsule.fromBytes(data);
    }

    public static void main(String args[]) throws NoSuchAlgorithmException
    {
        System.out.println("Proxy class Test!.");
        KeyPair kp = Proxy.generateKeyPair();
        PublicKey pk = kp.getPublicKey();
        PrivateKey sk = kp.getPrivateKey();

        List<Object> cp = Proxy.encapsulate(pk);

        Capsule capsule = (Capsule) cp.get(0);
        byte[] capsuleByte = capsule.toBytes();

        Capsule capsuleFrom = Proxy.capsuleFromBytes(capsuleByte);
        byte[] capsuleFromByte = capsuleFrom.toBytes();

        System.out.println("Capsuls check!");
        System.out.println(ProxyUtils.toHex(capsuleByte));
        System.out.println(ProxyUtils.toHex(capsuleFromByte));
     
        System.out.println("Decapsulate Original!");
        Scalar symmetricKey = (Scalar) cp.get(1);

        Scalar decapsulatedSymmetricKey = Proxy.decapsulate(capsule, sk);
        System.out.println(ProxyUtils.toHex(symmetricKey.toBytes()));  
        System.out.println(ProxyUtils.toHex(decapsulatedSymmetricKey.toBytes()));  
        
        System.out.println("\nReKey test!");
        KeyPair kpB = Proxy.generateKeyPair();

        PrivateKey skB = kpB.getPrivateKey();
        PublicKey pkB = kpB.getPublicKey();

        ReEncryptionKey rkAB = Proxy.generateReEncryptionKey(sk, pkB);

        Capsule reCapsule = Proxy.reEncryptCapsule(capsule, rkAB);
        byte[] reCapsuleByte = reCapsule.toBytes();

        Capsule reCapsuleFrom = Proxy.capsuleFromBytes(reCapsuleByte);
        byte[] reCapsuleFromByte = reCapsuleFrom.toBytes();

        System.out.println("\nReCapsuls check!");
        System.out.println(ProxyUtils.toHex(reCapsuleByte));
        System.out.println(ProxyUtils.toHex(reCapsuleFromByte));

        System.out.println("\n Decapsulate ReCapsule!");        
        
        Scalar decapsulatedReSymmetricKey = Proxy.decapsulate(reCapsule, skB);
        System.out.println(ProxyUtils.toHex(symmetricKey.toBytes()));  
        System.out.println(ProxyUtils.toHex(decapsulatedReSymmetricKey.toBytes()));  

    }
}
