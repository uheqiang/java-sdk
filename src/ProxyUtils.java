import java.math.BigInteger;
import java.util.Arrays;
import java.lang.StringBuilder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ProxyUtils
{
    public static String toHex(byte[] data)
    {
        StringBuilder st = new StringBuilder();
        for (byte b : data) {
            st.append(String.format("%02X", b));
        }
        return st.toString();
    }

    public static byte[] fromHex(String hexString)
    {
        byte[] data = new byte[hexString.length() / 2];
        for (int i = 0; i < data.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(hexString.substring(index, index + 2), 16);
            data[i] = (byte) j;
        }
        return data;
    }

    public static Scalar SHA256(GroupElement obj) throws NoSuchAlgorithmException
    {
         MessageDigest md = MessageDigest.getInstance("SHA-256");
         md.update(obj.toBytes());
         byte[] dg = md.digest();

         return new Scalar(new BigInteger(dg), new Curve("secp256k1"));
    }

    public static Scalar hashToScalar(GroupElement[] points) throws NoSuchAlgorithmException
    {
         MessageDigest md = MessageDigest.getInstance("SHA-256");
         for(int i = 0; i < points.length; i++)
         {
             md.update(points[i].toBytes());
         } 
         byte[] dg = md.digest();
         BigInteger bn = new BigInteger(dg);
         return new Scalar(bn.add(BigInteger.ONE), new Curve("secp256k1"));
    }

}

