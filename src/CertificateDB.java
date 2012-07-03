import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.cert.Certificate;



import sun.misc.BASE64Decoder; 
import sun.misc.BASE64Encoder; 


public class CertificateDB{
  
	public static final String beginCertString="-----BEGIN CERTIFICATE-----\r\n"; 
	public static final String endCertString="\r\n-----END CERTIFICATE-----\r\n";
	
   public static final String JAVABRIDGE_PORT="8087";
 
   static final php.java.bridge.JavaBridgeRunner runner = 
		  								php.java.bridge.JavaBridgeRunner.getInstance(JAVABRIDGE_PORT);
  
   private static String ksPath;
   private static String ksPassword="a10097"; 

   	public static void main(String args[]) throws Exception {
	  ksPath="c:\\temp\\certificateDB\\temp.keyStore"; 
    runner.waitFor();
    System.exit(0);
   	}

  	public static String saveData(String[] args){
  		String taskId=args[0]; 
  		String data=args[1];
  		String kind=args[2];
  		String algorithem=args[3];
  		KeyStore ks; 	 
	  
	  if(!kind.equals("secret key")&&(!kind.equals("certificate"))){
		  return "error :unknwon data "+kind ; 
	  }
	  
	  try{		  
		  ks=loadKeyStore();		  	  
	  }catch (Exception e) {
		 return "error : while trying to load key store , exception msg : " + e.getMessage();
	  }
	  if(kind.equals("secert key")){
		  try{
			  addSecretToKeystore(ks,taskId,data,algorithem); 
		  }
		  catch (Exception e) {
			  return "error : can't add this secert key to key store , exception msg : " + e.getMessage();
		}
	  }
	  if(kind.equals("certificate")){
		  try{
			 addCertToKeyStore(ks,taskId,data,algorithem);  
		  }
		  catch (Exception e) {
			  return "error : can't add this certificate key to key store , exception msg : " + e.getMessage();
		}
	  }
	  try {
		storeKeyStore(ks); 
	} catch (Exception e) {
		return "error : can't store key store , exception msg : " + e.getMessage();
	}
	  return "ok";
	  
	 
	 
	  
  }
 
  	public static String getData(String[] args){
  		
  		String taskId=args[0];
  		String kind=args[1]; 
  		
	  	  KeyStore ks; 
	  	  if(!kind.equals("secret key")&&(!kind.equals("certificate"))){
	  		  return "error :unknwon data" ; 
		  }
	  	  try{		  
			  ks=loadKeyStore();		  	  
		  }catch (Exception e) {
			 return "error : while trying to load key store , exception msg : " + e.getMessage();
		  }
		  if(kind.equals("secert key")){
			  try{
				 Key key=ks.getKey(taskId,ksPassword.toCharArray());
				 byte[] encodeBytes=key.getEncoded(); 
				 BASE64Encoder enc=new BASE64Encoder(); 
				 return enc.encode(encodeBytes); 
				 
			  }
			  catch (Exception e) {
				  return "error : can't get this key form keystore : " + e.getMessage();
			}
		  }
		  if(kind.equals("certificate")){
			  try{
				Certificate cert=ks.getCertificate(taskId); 
				BASE64Encoder base64Encoder=new BASE64Encoder(); 
				byte[] certBytes=cert.getEncoded();
				String crtBody=base64Encoder.encode(certBytes); 
				String crtFinal=beginCertString+crtBody+endCertString;
				return crtFinal; 
			  }
			  catch (Exception e) {
				  return "error : can't add this certificate key to key store , exception msg : " + e.getMessage();
			}
		  }
	 
		  return "error :unknwon data" ;  
  		
  	}
  	
	private static void addCertToKeyStore(KeyStore ks, String taskId,
			String data, String algorithem) throws Exception {
		CertificateFactory cf=CertificateFactory.getInstance(algorithem);
		InputStream in=new ByteArrayInputStream(data.getBytes()); 
		Certificate cert=cf.generateCertificate(in); 
		ks.setCertificateEntry(taskId, cert); 
		
		
	}

	private static void addSecretToKeystore(KeyStore ks, String alias, String data,String alg) throws Exception {
		BASE64Decoder		decoder=new BASE64Decoder(); 
		byte[]				binData=decoder.decodeBuffer(data);
		ks.setKeyEntry(alias,binData,null); 
	}

	private static KeyStore loadKeyStore() throws  Exception {
		
		InputStream instream = null;
		KeyStore keyStore;
		
		try{
			keyStore = KeyStore.getInstance("JCEKS");	 		
			instream = new FileInputStream(new File(ksPath));  
			keyStore.load(instream, ksPassword.toCharArray());
		
           } 
			catch (Exception e) {
			 throw e; 
			}
			finally {
               try { instream.close(); } catch (Exception ignore) {  }
           }
           return keyStore; 
	}
	
	private static  void storeKeyStore(KeyStore ks) throws Exception {
		OutputStream os; 
		try{
		File file=new File(ksPath); 
		if(!file.exists()){
			file.createNewFile();
		}
		 os=new FileOutputStream(file); 
		} catch (Exception e) {
			throw e; 
		}
		
		try {
			ks.store(os, ksPassword.toCharArray());
		} 
		catch (Exception e){
			throw e; 
		}
		try {
			os.close();
		} catch (IOException e) {
			throw e; 
		} 
	}
  
 }