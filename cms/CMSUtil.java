package cms;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;

import cms.SM2SignUtil;
import cms.SM2Signature;

/**
 * sm2 cms
 * @author luoyw
 */
public class CMSUtil
{
    private static boolean isDebug = false;
    
    /**
     * sm2 pkcs7/cms
     * @param cert
     * @param prikey
     * @param content
     * @return base64 String or null
     * @throws Exception
     */
    public static String doSM2Sign(X509Certificate cert,PrivateKey prikey,byte[] signbyte) throws Exception
    {
        try {
            ExternalSignatureSignerInfoGenerator signerGenerator = 
                new ExternalSignatureSignerInfoGenerator(GMObjectIdentifiers.sm3.getId(), GMObjectIdentifiers.sm2p256v1.getId());
            
            ExternalSignatureCMSSignedDataGenerator gen = new ExternalSignatureCMSSignedDataGenerator();
            CMSTypedData msg = new CMSProcessableByteArray(CMSObjectIdentifiersSM2.data,
                signbyte);
            byte[] bytesToSign = signerGenerator.getBytesToSign(
                CMSObjectIdentifiersSM2.data, msg, "BC");
            BigInteger[] signed = SM2SignUtil.signReturnBigInt(signbyte, (X509Certificate)cert, prikey);
            SM2Signature asn1Primitive = new SM2Signature(signed[0],signed[1]);
            byte[] signedBytes = asn1Primitive.getEncoded();
            byte[] certBytes = cert.getEncoded(); // will contain DER encoded
            
            if ((certBytes != null) && (signedBytes != null)) {
                // generator
                signerGenerator.setCertificate((X509Certificate)cert);
                signerGenerator.setSignedBytes(signedBytes);
                gen.addSignerInf(signerGenerator);
                ArrayList certList = new ArrayList();
                certList.add(cert);
                CertStore store = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
                gen.addCertificatesAndCRLs(store);
                // Finally, generate CMS message.
                CMSSignedData sigData = gen.generate(msg, true);
                Base64 encoder = new Base64();
                ContentInfo contentInfo = sigData.toASN1Structure();
                String signedContent = new String(encoder.encode(contentInfo.getEncoded(ASN1Encoding.DER)));
                System.out.println("Signed content: dl  " + signedContent + "\n");
                return signedContent;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    
    
    /**
     * sm2 pkcs7验签
     * @param signedData
     * @return true or false
     * @throws Exception
     */
    public static boolean doSM2Verify(String signedData)
        throws Exception
    {
        
        String p7 ="MIIEDwYKKoEcz1UGAQQCAqCCA/8wggP7AgEBMQ4wDAYIKoEcz1UBgxEFADAeBgoqgRzPVQYBBAIBoBAEDm1lc3NhZ2UgZGlnZXN0oIICyDCCAsQwggJpoAMCAQICCEeft5WusTgcMAwGCCqBHM9VAYN1BQAwgYIxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ2RvbmcxETAPBgNVBAcMCFNoZW56aGVuMScwJQYDVQQKDB5TaGVuWmhlbiBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxDTALBgNVBAsMBHN6Y2ExFDASBgNVBAMMC1NaQ0EgU00yIENBMB4XDTE3MDgwMTA2NDQwMFoXDTE4MDgwMTA2NDQwMFowXjELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeW5v+S4nOecgTESMBAGA1UEBwwJ5Lic6I6e5biCMQowCAYDVQQMDAExMQwwCgYDVQQLDANzbTIxDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARgctAZIAZlsxu/F1DWCvTCsCGPW/kBH+j7X4sbaKE4JfepP/oyTGBmERaQiNYxZ8gwnDfgH0htwIy95shAbP49o4HpMIHmMB8GA1UdIwQYMBaAFEXqN41yP7WmBG/DKsmt3e7my06NMBAGCCpWCweDzOl8BAQMAjExMDkGA1UdIAQyMDAwLgYEVR0gADAmMCQGCCsGAQUFBwIBFhhodHRwOi8vMTI3LjAuMC4xL2Nwcy5odG0wDAYDVR0TBAUwAwEBADAqBgNVHR8EIzAhMB+gHaAbhhlodHRwOi8vMTI3LjAuMC4xL2NybDUuY3JsMBAGCCpWCweDzOl5BAQMAjIyMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUJ1SE4GLfm5cEJbVu5wc3dSWP8RgwDAYIKoEcz1UBg3UFAANHADBEAiBkQRn+tSbPGmfKbPxTgnLwLPs7WSqnowcUt3vGvxWXjQIgO2O/Z7tc8TY4k0lVDY5xfnOpUXh929CysrlDrlxcUBgxgfkwgfYCAQEwgY8wgYIxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ2RvbmcxETAPBgNVBAcMCFNoZW56aGVuMScwJQYDVQQKDB5TaGVuWmhlbiBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxDTALBgNVBAsMBHN6Y2ExFDASBgNVBAMMC1NaQ0EgU00yIENBAghHn7eVrrE4HDAKBggqgRzPVQGDETAKBggqgRzPVQGCLQRHMEUCIQD8y5ZXZiZxIz1KDzyRQAPJq00GErNWeSvxCbH+3IseLQIgvSO8hzOmR+0+lkiu4auDPzRvdR/aJoASKr4/IldX9rQ=";
//          FileOutputStream fileOutputStream = new FileOutputStream("C:\\Users\\jeffrey\\Downloads\\89.p7s");
        ByteArrayInputStream inStream = new ByteArrayInputStream(Base64.decode(signedData));
        CMSSignedData cmsSingedData = new CMSSignedData(inStream);
        ASN1InputStream ais = new ASN1InputStream( Base64.decode(p7));
        while (isDebug && ais.available() > 0){
            ASN1Primitive obj = ais.readObject();
            System.out.println("version "+cmsSingedData.getVersion());
            System.out.println("getSignedContentTypeOID:"+cmsSingedData.getSignedContentTypeOID());
            System.out.println("isCertificateManagementMessage "+cmsSingedData.isCertificateManagementMessage());
            System.out.println("isDetachedSignature "+cmsSingedData.isDetachedSignature());
            System.out.println("getEncoded "+cmsSingedData.getEncoded().length);
            System.out.println("getDigestAlgorithmIDs "+cmsSingedData.getDigestAlgorithmIDs().toArray());
            //dump
            System.out.println(ASN1Dump.dumpAsString(obj, true));
            
         }
        
        byte[] planText;

        
        byte[] signed = null;
        X509Certificate cert = null;
        Security.addProvider(new BouncyCastleProvider());
        if(cmsSingedData.getSignedContent().getContent() != null ){
            
            Object content = cmsSingedData.getSignedContent().getContent();
            if( content instanceof DERPrintableString){
                planText = ((DERPrintableString)content).getOctets();
            }else{
                planText = (byte[]) (cmsSingedData.getSignedContent().getContent());
            }
        }
        CollectionStore x509s = (CollectionStore)cmsSingedData.getCertificates();
        X509CertificateHolder holder = (X509CertificateHolder)x509s.iterator().next();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(holder.getEncoded());
        cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        
        CMSTypedData cmsTypeDatas = cmsSingedData.getSignedContent();
        
        Object og = cmsSingedData.getSignerInfos();
        SignerInformationStore signers = cmsSingedData.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            signed = signer.getSignature();
        }
        System.out.println("length " + signed.length);
        return SM2SignUtil.verifySign(signed, planText, cert);
        
    }

    

    /**
     * Convert byte[] to S/MIME string
     * @param data
     * @return
     */
    public static String binaryToSmime(byte[] data) {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PKCS7-----\n");
        for (int i = 0; i < data.length; ) {
            byte[] chunk = Arrays.copyOfRange(data, i, (i + 63));
            sb.append(new String(chunk));
            sb.append("\n");
            i += 63;
        }
        sb.append("-----END PKCS7-----");
        return sb.toString();
    }

}
