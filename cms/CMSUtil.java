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

import org.apache.log4j.Logger;
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


/**
 * sm2 cms签名格式封装 基于bouncycastle、j4sign
 * 
 * @author luoyw
 */
public class CMSUtil {
	private static boolean isDebug = false;
	private static final Logger logger = Logger.getLogger(CMSUtil.class);

	public static void main(String[] args) throws Exception {
		// doSign();
		doVerify();
	}

	/**
	 * sm2 pkcs7 签名格式
	 * 
	 * @param cert
	 * @param prikey
	 * @param content
	 * @return base64 String or null
	 * @throws Exception
	 */
	public static String doSM2Sign(X509Certificate cert, PrivateKey prikey,
			byte[] signbyte) throws Exception {
		try {
			ExternalSignatureSignerInfoGenerator signerGenerator = new ExternalSignatureSignerInfoGenerator(
					GMObjectIdentifiers.sm3.getId(),
					GMObjectIdentifiers.sm2p256v1.getId());

			ExternalSignatureCMSSignedDataGenerator gen = new ExternalSignatureCMSSignedDataGenerator();
			CMSTypedData msg = new CMSProcessableByteArray(
					CMSObjectIdentifiersSM2.data, signbyte);
			BigInteger[] signed = SM2SignUtil.signReturnBigInt(signbyte,
					(X509Certificate) cert, prikey);
			SM2Signature asn1Primitive = new SM2Signature(signed[0], signed[1]);
			byte[] signedBytes = asn1Primitive.getEncoded();
			byte[] certBytes = cert.getEncoded(); // will contain DER encoded

			if ((certBytes != null) && (signedBytes != null)) {
				// generator
				signerGenerator.setCertificate((X509Certificate) cert);
				signerGenerator.setSignedBytes(signedBytes);
				gen.addSignerInf(signerGenerator);
				ArrayList certList = new ArrayList();
				certList.add(cert);
				CertStore store = CertStore.getInstance("Collection",
						new CollectionCertStoreParameters(certList), "BC");
				gen.addCertificatesAndCRLs(store);
				// Finally, generate CMS message.
				CMSSignedData sigData = gen.generate(msg, false);
				Base64 encoder = new Base64();
				// generator.
				ContentInfo contentInfo = sigData.toASN1Structure();
				String signedContent = new String(encoder.encode(contentInfo
						.getEncoded(ASN1Encoding.DER)));
				System.out.println("Signed content: dl  " + signedContent
						+ "\n");
				return signedContent;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	/**
	 * sm2 pkcs7验签
	 * 
	 * @param signedData
	 * @return true or false
	 * @throws Exception
	 */
	public static boolean doSM2Verify(String signedData) throws Exception {
		logger.info(signedData);
		byte[] signByte = Base64.decode(signedData);
		logger.info(222);
		ByteArrayInputStream inStream = new ByteArrayInputStream(signByte);
		CMSSignedData cmsSingedData = new CMSSignedData(inStream);
		byte[] planText = null;
		ASN1InputStream ais = new ASN1InputStream(signByte);
		logger.info(signByte);
		while (ais.available() > 0) {
			ASN1Primitive obj = ais.readObject();
		}
		// 签名值
		byte[] signed = null;
		X509Certificate cert = null;
		Security.addProvider(new BouncyCastleProvider());
		if (cmsSingedData.getSignedContent().getContent() != null) {

			Object content = cmsSingedData.getSignedContent().getContent();
			if (content instanceof DERPrintableString) {
				planText = ((DERPrintableString) content).getOctets();
			} else {
				planText = (byte[]) (cmsSingedData.getSignedContent()
						.getContent());
			}
		}
		// planText = (byte[]) (cmsSingedData.getSignedContent().getContent());
		CollectionStore x509s = (CollectionStore) cmsSingedData
				.getCertificates();
		// System.out.println("原文=" + new String(planText));
		X509CertificateHolder holder = (X509CertificateHolder) x509s.iterator()
				.next();
		InputStream in = new ByteArrayInputStream(holder.getEncoded());
		cert = new JcaX509CertificateConverter().setProvider("BC")
				.getCertificate(holder);
		// 获得证书信息
		CMSTypedData cmsTypeDatas = cmsSingedData.getSignedContent();
		// 获得签名者信息
		Object og = cmsSingedData.getSignerInfos();
		SignerInformationStore signers = cmsSingedData.getSignerInfos();
		Collection c = signers.getSigners();
		Iterator it = c.iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			signed = signer.getSignature();
		}
		System.out.println("签名值length=" + signed.length);
		return SM2SignUtil.verifySign(signed, planText, cert);

	}

	private static void doSign() throws UnrecoverableKeyException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException {
		ExternalSignatureSignerInfoGenerator signerGenerator = new ExternalSignatureSignerInfoGenerator(
				GMObjectIdentifiers.sm3.getId(),
				GMObjectIdentifiers.sm2p256v1.getId());

		ExternalSignatureCMSSignedDataGenerator gen = new ExternalSignatureCMSSignedDataGenerator();
		// String gg =
		// "MIICxDCCAmmgAwIBAgIIR5+3la6xOBwwDAYIKoEcz1UBg3UFADCBgjELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCUd1YW5nZG9uZzERMA8GA1UEBwwIU2hlbnpoZW4xJzAlBgNVBAoMHlNoZW5aaGVuIENlcnRpZmljYXRlIEF1dGhvcml0eTENMAsGA1UECwwEc3pjYTEUMBIGA1UEAwwLU1pDQSBTTTIgQ0EwHhcNMTcwODAxMDY0NDAwWhcNMTgwODAxMDY0NDAwWjBeMQswCQYDVQQGEwJDTjESMBAGA1UECAwJ5bm/5Lic55yBMRIwEAYDVQQHDAnkuJzojp7luIIxCjAIBgNVBAwMATExDDAKBgNVBAsMA3NtMjENMAsGA1UEAwwEdGVzdDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABGBy0BkgBmWzG78XUNYK9MKwIY9b+QEf6PtfixtooTgl96k/+jJMYGYRFpCI1jFnyDCcN+AfSG3AjL3myEBs/j2jgekwgeYwHwYDVR0jBBgwFoAUReo3jXI/taYEb8Mqya3d7ubLTo0wEAYIKlYLB4PM6XwEBAwCMTEwOQYDVR0gBDIwMDAuBgRVHSAAMCYwJAYIKwYBBQUHAgEWGGh0dHA6Ly8xMjcuMC4wLjEvY3BzLmh0bTAMBgNVHRMEBTADAQEAMCoGA1UdHwQjMCEwH6AdoBuGGWh0dHA6Ly8xMjcuMC4wLjEvY3JsNS5jcmwwEAYIKlYLB4PM6XkEBAwCMjIwCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBQnVITgYt+blwQltW7nBzd1JY/xGDAMBggqgRzPVQGDdQUAA0cAMEQCIGRBGf61Js8aZ8ps/FOCcvAs+ztZKqejBxS3e8a/FZeNAiA7Y79nu1zxNjiTSVUNjnF+c6lReH3b0LKyuUOuXFxQGA==";
		File file = new File("F:\\sm2.pfx");
		InputStream in1 = new FileInputStream(file);
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		KeyStore keyStore = KeyStore.getInstance("PKCS12", provider);
		//
		keyStore.load(in1, "123456".toCharArray());
		//
		Enumeration<String> enumas = keyStore.aliases();
		String keyAlias = null;

		if (enumas.hasMoreElements()) {
			keyAlias = (String) enumas.nextElement();
			System.out.println(keyAlias);
		}
		java.security.cert.Certificate cert = keyStore.getCertificate(keyAlias);
		PrivateKey prikey = (PrivateKey) keyStore.getKey(keyAlias,
				"123456".toCharArray());
		X509CertificateHolder signCert;
		// add certificate for buildSigningCertificateV2Attribute method used in
		// getBytesToSign
		signerGenerator.setCertificate((X509Certificate) cert);

		// gen.addSignerInf(signerGenerator);
		try {
			// Obtain bytes to sign;
			// note that this implementation includes a timestamp
			// as an authenticated attribute, then bytesToSign is every time
			// different,
			// even if signing the same data.
			// The timestamp should be notified and accepted by the signer along
			// data to sign
			// BEFORE he applies encryption with his private key.
			// The timestamp is used during verification to check that signature
			// time is
			// in signing certificate validity time range.

			// bytes of file to be signed in base64
			byte[] signbyte = "message digest".getBytes();
			/*
			 * CMSTypedData msg = new
			 * CMSProcessableByteArray(CMSObjectIdentifiersSM2.data, signbyte);
			 */
			CMSTypedData msg = new CMSProcessableByteArray(signbyte);

			byte[] bytesToSign = signerGenerator.getBytesToSign(
					CMSObjectIdentifiersSM2.data, msg, "BC");
			// Digest generation. Digest algorithm must match the one passed to
			// ExternalSignatureSignerInfoGenerator
			// constructor above (SHA1, in this case).
			BigInteger[] signed = SM2SignUtil.signReturnBigInt(signbyte,
					(X509Certificate) cert, prikey);
			SM2Signature asn1Primitive = new SM2Signature(signed[0], signed[1]);
			byte[] signedBytes = asn1Primitive.getEncoded();
			// digest

			byte[] certBytes = cert.getEncoded(); // will contain DER encoded

			if ((certBytes != null) && (signedBytes != null)) {
				signerGenerator.setCertificate((X509Certificate) cert);
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
				// generator.
				ContentInfo contentInfo = sigData.toASN1Structure();
				String signedContent = new String(encoder.encode(contentInfo
						.getEncoded("DER")));
				p7 = signedContent;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		// 1790591505
		// 109962338
	}

	public static char byte2char(byte b) {
		return (char) b;
	}

	static String p7;

	private static void doVerify() throws Exception {

		// p7
		// ="MIIEDwYKKoEcz1UGAQQCAqCCA/8wggP7AgEBMQ4wDAYIKoEcz1UBgxEFADAeBgoqgRzPVQYBBAIBoBAEDm1lc3NhZ2UgZGlnZXN0oIICyDCCAsQwggJpoAMCAQICCEeft5WusTgcMAwGCCqBHM9VAYN1BQAwgYIxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ2RvbmcxETAPBgNVBAcMCFNoZW56aGVuMScwJQYDVQQKDB5TaGVuWmhlbiBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxDTALBgNVBAsMBHN6Y2ExFDASBgNVBAMMC1NaQ0EgU00yIENBMB4XDTE3MDgwMTA2NDQwMFoXDTE4MDgwMTA2NDQwMFowXjELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeW5v+S4nOecgTESMBAGA1UEBwwJ5Lic6I6e5biCMQowCAYDVQQMDAExMQwwCgYDVQQLDANzbTIxDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARgctAZIAZlsxu/F1DWCvTCsCGPW/kBH+j7X4sbaKE4JfepP/oyTGBmERaQiNYxZ8gwnDfgH0htwIy95shAbP49o4HpMIHmMB8GA1UdIwQYMBaAFEXqN41yP7WmBG/DKsmt3e7my06NMBAGCCpWCweDzOl8BAQMAjExMDkGA1UdIAQyMDAwLgYEVR0gADAmMCQGCCsGAQUFBwIBFhhodHRwOi8vMTI3LjAuMC4xL2Nwcy5odG0wDAYDVR0TBAUwAwEBADAqBgNVHR8EIzAhMB+gHaAbhhlodHRwOi8vMTI3LjAuMC4xL2NybDUuY3JsMBAGCCpWCweDzOl5BAQMAjIyMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUJ1SE4GLfm5cEJbVu5wc3dSWP8RgwDAYIKoEcz1UBg3UFAANHADBEAiBkQRn+tSbPGmfKbPxTgnLwLPs7WSqnowcUt3vGvxWXjQIgO2O/Z7tc8TY4k0lVDY5xfnOpUXh929CysrlDrlxcUBgxgfkwgfYCAQEwgY8wgYIxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ2RvbmcxETAPBgNVBAcMCFNoZW56aGVuMScwJQYDVQQKDB5TaGVuWmhlbiBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxDTALBgNVBAsMBHN6Y2ExFDASBgNVBAMMC1NaQ0EgU00yIENBAghHn7eVrrE4HDAKBggqgRzPVQGDETAKBggqgRzPVQGCLQRHMEUCIQD8y5ZXZiZxIz1KDzyRQAPJq00GErNWeSvxCbH+3IseLQIgvSO8hzOmR+0+lkiu4auDPzRvdR/aJoASKr4/IldX9rQ=";
		// FileOutputStream fileOutputStream = new
		// FileOutputStream("C:\\Users\\jeffrey\\Downloads\\89.p7s");
		// fileOutputStream.write(Base64.decode(p7));
		// System.out.println(Base64.decode(p7).length);
		// System.out.println(Base64.decode(p).length);
		String p7 = "MIIFbwYJKoZIhvcNAQcCoIIFYDCCBVwCAQMxDjAMBggqgRzPVQGDEQUAMB0GCSqGSIb3DQEHAaAQBA5tZXNzYWdlIGRpZ2VzdKCCAtQwggLQMIICdKADAgECAggRDDRgFH+CiDAMBggqgRzPVQGDdQUAMIGCMQswCQYDVQQGEwJDTjESMBAGA1UECAwJR3Vhbmdkb25nMREwDwYDVQQHDAhTaGVuemhlbjEnMCUGA1UECgweU2hlblpoZW4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MQ0wCwYDVQQLDARzemNhMRQwEgYDVQQDDAtTWkNBIFNNMiBDQTAeFw0xNzA3MTIxMDU4MThaFw0xODA3MTIxMDU4MThaMGExCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAnlub/kuJznnIExEjAQBgNVBAcMCea3seWcs+W4gjELMAkGA1UECgwCMTExCzAJBgNVBAsMAjExMRAwDgYDVQQDDAdTbTJ0ZXN0MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBA0IABKxOBrWEItr0LoSK4Obcx57qe6hVYvu60jHdCF8FIjDxYLPQWhODesz82WwC0LF0o9Wt5cNjRLX8m9vIP5nVedqjFjAUMBIGBmCBHIbvJAQIDAYyMTQzMjQwDAYIKoEcz1UBg3UFAANIADBFAiEA5orA0oTes55JPk5IxbhM/3gOZ38s27TBGRAYHKRHuaUCIDjYjgrcxlw6hpbbluwc060b3B+2LcuJWSigJNZ4qad5MYICTjCCAkoCAQEwgY8wgYIxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ2RvbmcxETAPBgNVBAcMCFNoZW56aGVuMScwJQYDVQQKDB5TaGVuWmhlbiBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxDTALBgNVBAsMBHN6Y2ExFDASBgNVBAMMC1NaQ0EgU00yIENBAggRDDRgFH+CiDAMBggqgRzPVQGDEQUAoIIBTDAZBgkqhkiG9w0BCQMxDAYKKoEcz1UGAQQCATAcBgkqhkiG9w0BCQUxDxcNMTgwMzEyMDgyMzMzWjAvBgkqhkiG9w0BCQQxIgQgxSKpQuib2A2X3WZuelUxs2GIyYFxSemyWN/lHs6Y7Xcwgd8GCyqGSIb3DQEJEAIvMYHPMIHMMIHJMIHGMAoGCCqBHM9VAYMRBCAu+tACXPJBI5bRbqOBlbpgsO01Pu7b1voXtB3drVg5mTCBlTCBiKSBhTCBgjELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCUd1YW5nZG9uZzERMA8GA1UEBwwIU2hlbnpoZW4xJzAlBgNVBAoMHlNoZW5aaGVuIENlcnRpZmljYXRlIEF1dGhvcml0eTENMAsGA1UECwwEc3pjYTEUMBIGA1UEAwwLU1pDQSBTTTIgQ0ECCBEMNGAUf4KIMAwGCCqBHM9VAYItBQAERzBFAiEA4IUWYsJpOE2vIhY7YL9SXcXQUUqM/70W7kKvHh5014YCIEVBD1q4tmVBO67G+tDKxP2B3QKhAK3wRhalAebUl/To";
		// String p7 =
		// "MIID9AYKKoEcz1UGAQQCAqCCA+QwggPgAgEBMQ4wDAYIKoEcz1UBgxEFADAcBgoqgRzPVQYBBAIBoA4EDFNaQ0FUZXN0RGF0YaCCAq4wggKqMIICTqADAgECAgh4D50V+kjlCDAMBggqgRzPVQGDdQUAMIGCMQswCQYDVQQGEwJDTjESMBAGA1UECAwJR3Vhbmdkb25nMREwDwYDVQQHDAhTaGVuemhlbjEnMCUGA1UECgweU2hlblpoZW4gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MQ0wCwYDVQQLDARzemNhMRQwEgYDVQQDDAtTWkNBIFNNMiBDQTAeFw0xODAyMDEwMzI5MzRaFw0xOTAyMDEwMzI5MzRaMGcxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAnlub/kuJznnIExEjAQBgNVBAcMCeS4nOiOnuW4gjENMAsGA1UEDAwEMTExMTEOMAwGA1UECwwFMTExMTExETAPBgNVBAMMCHdhdzExMTExMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEGQHwhogJ8JP/Go3JZD5wEEKfHy8Tb5WmRHMMoVWSaEf8PeV59GCKftyHvakzoLidUR/HujX+Oh4Y309rrAQukaOBxTCBwjAfBgNVHSMEGDAWgBRF6jeNcj+1pgRvwyrJrd3u5stOjTA5BgNVHSAEMjAwMC4GBFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovLzEyNy4wLjAuMS9jcHMuaHRtMAwGA1UdEwQFMAMBAQAwKgYDVR0fBCMwITAfoB2gG4YZaHR0cDovLzEyNy4wLjAuMS9jcmw4LmNybDALBgNVHQ8EBAMCBsAwHQYDVR0OBBYEFE3HwZhzApvbtGcFLDECc+QjGeAuMAwGCCqBHM9VAYN1BQADSAAwRQIhANAx6OUxRj88Vle7zN2KK4IqTekWWmENmO/z7BddbBW9AiALlu93fzImFmZ63V+Xuz2IH2M9Mo2JKE4KSy8qZlnX/jGB+jCB9wIBATCBjzCBgjELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCUd1YW5nZG9uZzERMA8GA1UEBwwIU2hlbnpoZW4xJzAlBgNVBAoMHlNoZW5aaGVuIENlcnRpZmljYXRlIEF1dGhvcml0eTENMAsGA1UECwwEc3pjYTEUMBIGA1UEAwwLU1pDQSBTTTIgQ0ECCHgPnRX6SOUIMAoGCCqBHM9VAYMRMAsGCSqBHM9VAYItAQRHMEUCIGdz9YVXcy/9/BbzPWbfQd+yLYv35Gw3EiwlkfTDf1NxAiEAjZdAlCG24rD5FdLIF05ASvKMBIVBZ1FzCESwdhNaZGM=";
		ByteArrayInputStream inStream = new ByteArrayInputStream(
				Base64.decode(p7));
		CMSSignedData cmsSingedData = new CMSSignedData(inStream);
		ASN1InputStream ais = new ASN1InputStream(Base64.decode(p7));
		while (ais.available() > 0) {
			ASN1Primitive obj = ais.readObject();
			System.out.println(ASN1Dump.dumpAsString(obj, true));
			// System.out.println(CustomTreeNode.dumpAsString(obj));
		}
		// MyTestUtil.print(cmsSingedData);
		System.out.println("版本:" + cmsSingedData.getVersion());
		System.out.println("getSignedContentTypeOID:"
				+ cmsSingedData.getSignedContentTypeOID());
		System.out.println("isCertificateManagementMessage "
				+ cmsSingedData.isCertificateManagementMessage());
		System.out.println("isDetachedSignature "
				+ cmsSingedData.isDetachedSignature());
		System.out.println("getEncoded " + cmsSingedData.getEncoded().length);
		System.out.println("getDigestAlgorithmIDs "
				+ cmsSingedData.getDigestAlgorithmIDs().toArray());
		// System.out.println("getDigestAlgorithmIDs "+cmsSingedData.);
		// base64
		// new ASN1InputStream()-->ContentInfo(ASN1Sequence)

		// CMSSignedDataGenerator dataGenerator = new CMSSignedDataGenerator();
		// dataGenerator.addCertificate(paramX509CertificateHolder);
		List certs = new ArrayList();

		// CollectionStore x509s = new CollectionStore(certs);
		// dataGenerator.addCertificates(x509s);
		// dataGenerator.addSignerInfoGenerator(paramSignerInfoGenerator);
		List signerInfo = new ArrayList();
		// SignerInformation signer = new SignerInformation(signer);

		// SignerInformationStore signerInformationStore = new
		// SignerInformationStore(signerInfo);
		// dataGenerator.addSigners(signerInformationStore);
		// dataGenerator.generateCounterSigners(paramSignerInformation)
		// 原文
		byte[] planText = null;

		// 签名值
		byte[] signed = null;
		X509Certificate cert = null;
		Security.addProvider(new BouncyCastleProvider());
		if (cmsSingedData.getSignedContent().getContent() != null) {

			Object content = cmsSingedData.getSignedContent().getContent();
			if (content instanceof DERPrintableString) {
				planText = ((DERPrintableString) content).getOctets();
			} else {
				planText = (byte[]) (cmsSingedData.getSignedContent()
						.getContent());
			}
			// if( cmsSingedData.getSignedContent().getContent().toString()
			// instanceof )
		}
		// planText = (byte[]) (cmsSingedData.getSignedContent().getContent());
		CollectionStore x509s = (CollectionStore) cmsSingedData
				.getCertificates();
		System.out.println("原文=" + new String(planText));
		X509CertificateHolder holder = (X509CertificateHolder) x509s.iterator()
				.next();
		CertificateFactory certFactory = CertificateFactory
				.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(holder.getEncoded());
		cert = new JcaX509CertificateConverter().setProvider("BC")
				.getCertificate(holder);
		// 获得证书信息
		CMSTypedData cmsTypeDatas = cmsSingedData.getSignedContent();
		// 获得签名者信息
		Object og = cmsSingedData.getSignerInfos();
		SignerInformationStore signers = cmsSingedData.getSignerInfos();
		Collection c = signers.getSigners();
		Iterator it = c.iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			System.out.println("摘要算法 =" + signer.getDigestAlgOID());
			System.out.println("算法 =" + signer.getEncryptionAlgOID());
			signed = signer.getSignature();
			// planText = signer.getContentDigest();
		}
		System.out.println("签名值length=" + signed.length);
		System.out.println(SM2SignUtil.verifySign(signed, planText, cert));
	}

	/**
	 * Convert byte[] to S/MIME string
	 * 
	 * @param data
	 * @return
	 */
	public static String binaryToSmime(byte[] data) {
		StringBuilder sb = new StringBuilder();
		sb.append("-----BEGIN PKCS7-----\n");
		for (int i = 0; i < data.length;) {
			byte[] chunk = Arrays.copyOfRange(data, i, (i + 63));
			sb.append(new String(chunk));
			sb.append("\n");
			i += 63;
		}
		sb.append("-----END PKCS7-----");
		return sb.toString();
	}

}
