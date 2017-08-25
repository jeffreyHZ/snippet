package cms;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public abstract interface CMSObjectIdentifiersSM2
{
  public static final ASN1ObjectIdentifier data = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.1");
  public static final ASN1ObjectIdentifier signedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.2");
  public static final ASN1ObjectIdentifier envelopedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.3");
  public static final ASN1ObjectIdentifier signedAndEnvelopedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.4");
  public static final ASN1ObjectIdentifier digestedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.5");
  public static final ASN1ObjectIdentifier encryptedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.5");
}
