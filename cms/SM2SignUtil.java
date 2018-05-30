package com.szca.sm2;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

import sun.security.pkcs.ParsingException;

import com.szca.caau.webservice.util.FileUtil;
import com.szca.jcajce.provider.sm2.SM2ParameterSpec;
import com.szca.sm2.cms.CMSUtil;
import com.szca.sm2.cms.ExternalSignatureCMSSignedDataGenerator;
import com.szca.sm2.cms.ExternalSignatureSignerInfoGenerator;

public class SM2SignUtil
{
    private static byte[] SM2_USER_ID = "1234567812345678".getBytes();
    private static String fileSignedData; 
    private static X509Certificate cert;

    /**
    * PKCS1签名
    * @param signbyte
    *          待签名数据
    * @param cf
    *          签名证书
    * @param privateKey
    *          私钥
    * @return
    *      PKCS1格式签名值
    * @throws NoSuchAlgorithmException
    * @throws InvalidKeyException
    * @throws SignatureException
    * @throws IOException 
    */
   public static String sign(byte[] signbyte,X509Certificate cert,PrivateKey privateKey)
   throws NoSuchAlgorithmException,InvalidKeyException, SignatureException, IOException{
       // 生成签名
       BigInteger[] arrayOfBigInteger = signReturnBigInt(signbyte,cert,privateKey);
//       System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(arrayOfBigInteger[0]), 0, R, 0, 32);
//       System.arraycopy(BigIntegerUtil.asUnsigned32ByteArray(arrayOfBigInteger[1]), 0, S, 32, 32);
       SM2Signature asn1Primitive = new SM2Signature(arrayOfBigInteger[0],arrayOfBigInteger[1]);
       String encoded= Base64.toBase64String(asn1Primitive.toASN1Primitive().getEncoded());
       System.out.println(encoded);
       return encoded;
       
   }   
   
   public static BigInteger[] signReturnBigInt(byte[] signbyte,X509Certificate cert,PrivateKey privateKey){
       // 创建SM2Signer对象
       SM2Signer localSM2Signer = new SM2Signer();
       // 生成签名 TRUE
       BCECPrivateKey  szcaSm2PriK = (BCECPrivateKey) privateKey;
//       BCECPublicKey localECPublicKey = (BCECPublicKey)cert.getPublicKey();
       ECParameterSpec localECParameterSpec =  szcaSm2PriK.getParameters();
       ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
           localECParameterSpec.getG(), localECParameterSpec.getN());
       
       ECPrivateKeyParameters localECPrivateKeyParameters = new ECPrivateKeyParameters(szcaSm2PriK.getD(),localECDomainParameters);
       ParametersWithID parametersWithID = new ParametersWithID(localECPrivateKeyParameters,SM2_USER_ID);
       localSM2Signer.init(true, parametersWithID);
       BigInteger[] arrayOfBigInteger = localSM2Signer.generateSignature(signbyte);
       return arrayOfBigInteger;
   }
   
   /**
    * PKCS1 验证
    * @param signdate
    *          签名值勤
    * @param data
    *          原文
    * @param cf
    *          签名的证书
    * @return
    *      true 正确
    *      false 错误
    * @throws NoSuchAlgorithmException
    * @throws InvalidKeyException
    * @throws SignatureException
    * @throws IOException 
    */
   public static boolean verifySign(byte[] signdatebyte, byte[] databyte,X509Certificate cert) throws NoSuchAlgorithmException, 
   InvalidKeyException, SignatureException, IOException{
       SM2Signer localSM2Signer = new SM2Signer();
       Security.addProvider(new BouncyCastleProvider());
       PublicKey publicKey = cert.getPublicKey();
       ECPublicKeyParameters param = null;
       
       if (publicKey instanceof BCECPublicKey)
       {
           BCECPublicKey localECPublicKey = (BCECPublicKey)publicKey;
           ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
           ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
           localECParameterSpec.getG(), localECParameterSpec.getN());
           param = new ECPublicKeyParameters(localECPublicKey.getQ(),localECDomainParameters);
       }
       ByteArrayInputStream inStream = new ByteArrayInputStream(signdatebyte);
       ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
       ASN1Primitive derObject = asnInputStream.readObject();
       BigInteger R = null;
       BigInteger S = null;
       if (derObject instanceof ASN1Sequence) {  
           ASN1Sequence signSequence = (ASN1Sequence) derObject;  
           Enumeration<ASN1Integer> enumer = signSequence.getObjects();
               R =  ((ASN1Integer)enumer.nextElement()).getValue();
               S =  ((ASN1Integer)enumer.nextElement()).getValue();
       }
       ParametersWithID parametersWithID = new ParametersWithID(param,SM2_USER_ID);
       localSM2Signer.init(false, parametersWithID);
       

//       localSM2Signer.init(false, param);
       boolean res = localSM2Signer.verifySignature(databyte, BigIntegerUtil.toPositiveInteger(R.toByteArray()),
           BigIntegerUtil.toPositiveInteger(S.toByteArray()));
       return res;
   }
   

   /**
    * SM2 PKCS7 格式的签名
    * @param x509
    * @param privateKey
    * @param contentInfoS
    * @return base64 String or null
    * @throws Exception
    */
   public static String signwithContentInfoByPkcs7(X509Certificate x509,PrivateKey privateKey,String contentInfoS) throws 
   Exception{
       
       return CMSUtil.doSM2Sign(x509, privateKey, contentInfoS.getBytes());   
   }
   
   /**
    * SM2 PKCS7签名验签
    * @param pkcs7String
    *          PKCS7签名值
    * @return
    *      true 正确
    *      false 错误
 * @throws Exception 
    */
   public static boolean versignwithContentInfoByPkcs7(String pkcs7String) throws Exception{
       
       return CMSUtil.doSM2Verify(pkcs7String);
   }
   /**
    * PKCS1文件签名
    * @param filepath
    *          待签名文件路径
    * @param cf
    *          签名证书
    * @param privateKey
    *          私钥
    * @return
    *      签名值
    * @throws NoSuchAlgorithmException
    * @throws InvalidKeyException
    * @throws SignatureException
    * @throws IOException 
    */
   public static String filesign(String filepath,X509Certificate cf,PrivateKey privateKey) throws
   NoSuchAlgorithmException,InvalidKeyException, SignatureException, IOException{
       byte data[] = getByteArrayByFilePath(filepath);
       String signData = sign(data, cf, privateKey);
//       byte[] datanew=new byte[signData.length];
//       for(int i=0;i<signData.length;i++){
//           datanew[i]=signData[signData.length-i-1];
//       }
       return signData;
   }   
   
   @SuppressWarnings("unused")
    private static byte[] getByteArrayByFilePath(String filepath){
           
           FileChannel fc = null; 
           byte data[] = null;
           try {  
               fc = new RandomAccessFile(filepath, "r").getChannel();  
               MappedByteBuffer byteBuffer = fc.map(MapMode.READ_ONLY, 0,  
                       fc.size()).load();  
               data = new byte[(int) fc.size()];  
               if (byteBuffer.remaining() > 0) {  
                   byteBuffer.get(data, 0, byteBuffer.remaining());  
               }  
           } catch (IOException e) {  
               e.printStackTrace();  
           } finally {  
               try {
                   if(fc != null )
                   fc.close();  
               } catch (IOException e) {  
                   e.printStackTrace();  
               }  
           }
           return data;
     }
   
   /**
    * PKCS1 文件验证
    * @param signdate
    *          签名值勤
    * @param data
    *          原文
    * @param cf
    *          签名的证书
    * @return
    *      true 正确
    *      false 错误
    * @throws NoSuchAlgorithmException
    * @throws InvalidKeyException
    * @throws SignatureException
    * @throws IOException 
    */
   public static boolean verifyFileSign(byte[] signdatebyte, String datafile,X509Certificate cf) throws NoSuchAlgorithmException, 
   InvalidKeyException, SignatureException, IOException{
       byte databyte[] = getByteArrayByFilePath(datafile);
       return verifySign(signdatebyte, databyte, cf);
   }
   
   /**
    * PKCS7附原文(文件)签名 
    * @param x509
    *          证书
    * @param privateKey
    *          私钥
    * @param filepath
    *          待签名文件路径
    * @param outpath
    *          签名后文件输出路径
    * @return
    *      签名证书的主题
    * @throws KeyStoreException
    * @throws NoSuchAlgorithmException
    * @throws CertificateException
    * @throws IOException
    * @throws UnrecoverableKeyException
    * @throws InvalidKeyException
    * @throws SignatureException
    */
   public static String signFileWithContentInfoByPkcs7(X509Certificate cer, PrivateKey privatekey,
                                                   String filepath, String outpath)
   {
        byte[] data = getByteArrayByFilePath(filepath);   
        String siged;
        try
        {
            siged = CMSUtil.doSM2Sign(cer, privatekey, data);
            FileUtil.bigFileWriter(outpath, Base64.decode(siged.getBytes()));
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        } 
       return cer.getSubjectDN().getName();     
   }
   
   /**
    * PKCS7 文件验签
    * @param filepath
    *          签名文件
    * @param outpath
    *          原文输出文件
    * @return
    *      true 正确
    *      false 错误            
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws ParsingException
    * @throws IOException
    * @throws SignatureException
    */
   
   public static boolean verFileSignwithContentInfoByPkcs7(String filepath, String outpath) throws Exception
   {
       byte[] dst = FileUtil.bigFileReader(filepath);
       
       ByteArrayInputStream inStream = new ByteArrayInputStream(Base64.decode(dst));
       CMSSignedData cmsSingedData = new CMSSignedData(inStream);
       //原文
       byte[] planText = null;
       //签名值
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
       // 获得证书信息
       CMSTypedData cmsTypeDatas = cmsSingedData.getSignedContent();
       // 获得签名者信息
       Object og = cmsSingedData.getSignerInfos();
       SignerInformationStore signers = cmsSingedData.getSignerInfos();
       Collection c = signers.getSigners();
       Iterator it = c.iterator();
       while (it.hasNext())
       {
         SignerInformation signer = (SignerInformation)it.next();
         signed = signer.getSignature();
       }
       FileUtil.bigFileWriter(outpath, planText);
       return SM2SignUtil.verifySign(signed, planText, cert);
       
   }
   
   /**
    * PKCS7签名验签
    * @param pkcs7String
    *          PKCS7签名值
    * @return
    *      原文
    *      E404 错误
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidKeyException
    * @throws ParsingException
    * @throws IOException
    * @throws SignatureException
    */
   public static byte[] verFileSignwithContentInfoByPkcs7Stream(byte[] file)
   {
       try
       { 
           ByteArrayInputStream inStream = new ByteArrayInputStream(Base64.decode(file));
           CMSSignedData cmsSingedData;
           cmsSingedData = new CMSSignedData(inStream);
          
           //原文
           byte[] planText = null;
           //签名值
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
           // 获得证书信息
           CMSTypedData cmsTypeDatas = cmsSingedData.getSignedContent();
           // 获得签名者信息
           Object og = cmsSingedData.getSignerInfos();
           SignerInformationStore signers = cmsSingedData.getSignerInfos();
           Collection c = signers.getSigners();
           Iterator it = c.iterator();
           while (it.hasNext())
           {
             SignerInformation signer = (SignerInformation)it.next();
             signed = signer.getSignature();
           }
           if(SM2SignUtil.verifySign(signed, planText, cert)){
               return planText;
           }
       
       }
       catch (Exception e)
       {  e.printStackTrace();
       }
       
       return "E404".getBytes();
           
       }
   
   private static void doSign() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException
   {
       ExternalSignatureSignerInfoGenerator signerGenerator = 
           new ExternalSignatureSignerInfoGenerator(GMObjectIdentifiers.sm3.getId(), GMObjectIdentifiers.sm2p256v1.getId());
       
       ExternalSignatureCMSSignedDataGenerator gen = new ExternalSignatureCMSSignedDataGenerator();
       File file = new File("C:\\Users\\jeffrey\\Desktop\\hainan.pfx");
       InputStream in1 = new FileInputStream(file);
       BouncyCastleProvider provider = new BouncyCastleProvider();
       Security.addProvider(provider);
       KeyStore keyStore = KeyStore.getInstance("PKCS12");
       //     
       keyStore.load(in1, "123456".toCharArray());
       //     
       Enumeration<String> enumas = keyStore.aliases();
       String keyAlias = null;
       
       if (enumas.hasMoreElements())
       {
           keyAlias = (String)enumas.nextElement();
       }
       cert = (X509Certificate)keyStore.getCertificate(keyAlias);
       PrivateKey prikey = (PrivateKey)keyStore.getKey(keyAlias, "123456".toCharArray());
   }
   
   
   public static void main(String[] args) throws Exception
    {
//       byte[] ss = "data:image/png;base64,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".getBytes();
//       FileUtil.bigFileWriter("E://12.png", Base64.decode("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"));
       doSign();
//       System.out.println(verifyFileSign("data:image/png;base64,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".getBytes(), "E://Test//1.png", cert));;
    }

}
