package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * 12-byte crafted DER input triggers heap-sized allocation in
 * CertificateFactory via ASN1InputStream whose size limit defaulted to
 * Runtime.maxMemory().
 *
 * Fix: ASN1InputStream constructed with explicit 4 MB cap for certificates,
 * 32 MB for CRLs — both well above any legitimate structure.
 */
public class BcSecurityTest
    extends SimpleTest
{
    public String getName()
    {
        return "BcSecurityTest";
    }

    public void performTest()
        throws Exception
    {
        sec001_craftedDerRejectedInsteadOfOOM();
    }

    /**
     * bc-sec-001-oom.der is a 12-byte crafted DER structure whose inner
     * INTEGER length field equals Runtime.maxMemory() - 1. Before the fix,
     * DefiniteLengthInputStream.toByteArray() allocated that many bytes and
     * threw OutOfMemoryError. After the fix, the 4 MB cap causes the stream
     * to reject the oversized length field with CertificateException.
     */
    private void sec001_craftedDerRejectedInsteadOfOOM()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        try (InputStream in = BcSecurityTest.class.getResourceAsStream("bc-sec-001-oom.der"))
        {
            cf.generateCertificate(in);
            fail("expected CertificateException for oversized DER structure");
        }
        catch (CertificateException e)
        {
            // expected — oversized length field rejected by 4 MB cap
        }
        catch (OutOfMemoryError e)
        {
            fail("fix not applied — OOM triggered by crafted DER input");
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new BcSecurityTest());
    }
}
