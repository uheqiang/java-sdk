import java.math.BigInteger;
import java.util.Arrays;

public class Scalar
{

    private BigInteger scalar;
    private Curve curve;

    public Scalar(BigInteger sc, Curve crv){
        scalar = sc;
        curve = crv;
    }
    public int expectedByteOfLength()
    {
        return curve.getOrderSize();
    }

    public BigInteger getValue()
    {
        return scalar;
    }
    public byte[] toBytes()
    {
        return scalar.toByteArray();
    }

    public static Scalar fromBytes(byte[] data)
    {
         return new Scalar(new BigInteger(data), new Curve("secp256k1"));
    }

    public Scalar add(Scalar other)
    {
        return new Scalar(scalar.add(other.scalar), curve);
    }

    public Scalar mul(Scalar other)
    {
        return new Scalar(scalar.multiply(other.scalar).mod(curve.getOrder()), curve); //.mod(/* curve order*/));
    }

    public Scalar invm()
    {
        return new Scalar(scalar.modInverse(curve.getOrder()), curve);
    }

}

