import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger; 


public class Curve
{
    private String name;
    private ECNamedCurveParameterSpec curve;
    private ECPoint generator;
    private BigInteger order;
    private int order_size;

    public Curve(String curve_name)
    {
        name = curve_name;
        curve = ECNamedCurveTable.getParameterSpec(name);
        generator = curve.getG();
        order = curve.getN();
        order_size = order.bitLength() / 8;
    }

    public String getName()
    {
        return name;
    }
    public ECCurve getCurve()
    {
        return curve.getCurve();
    }
    public ECPoint getGenerator()
    {
        return generator;
    }

    public BigInteger getOrder()
    {
        return order;
    }
    public int getOrderSize()
    {
        return order_size;
    }
}
