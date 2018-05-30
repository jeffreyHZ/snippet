package cms;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class FileUtil {
	
	

	
	
	
	public  static byte[] bigFileReader(String filepath) throws IOException {
		 RandomAccessFile rafi = new RandomAccessFile(filepath, "r");
		 FileChannel fci = rafi.getChannel();
		 long size = fci.size();
		 MappedByteBuffer mbbi = fci.map(FileChannel.MapMode.READ_ONLY, 0, size);
		 //long start = System.currentTimeMillis();
		 byte[] dst=new byte[(int) size];
		 mbbi.get(dst);
		 fci.close();
		 rafi.close();		
		 return dst;
	}
	
	/**
	 * 计算文件HASH
	 * @param file  	
	 * 			文件的路径   
	 * @param hashType
	 * 			HASH摘要算法
	 * @return
	 * 			HASH值
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 */
	public static byte[] filehash(String file, String hashType) throws NoSuchAlgorithmException, IOException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1"); 
		FileInputStream in = new FileInputStream(file); 
		FileChannel ch = in.getChannel(); 
		MappedByteBuffer byteBuffer = ch.map(FileChannel.MapMode.READ_ONLY, 0, file.length()); 			
		ch.close();
		in.close();
		messageDigest.update(byteBuffer); 
		return messageDigest.digest();
	}
	
	/**
	 * 写文件
	 * @param filepath 要读文件路径
	 * @return 返回文件里的内容
	 * @throws IOException 
	 */
	public  static void bigFileWriter(String filepath,byte[] data) throws IOException{
		 FileOutputStream fos=new FileOutputStream(filepath);
		 fos.write(data);
		 fos.close();
	}
	static int length2 = 0x8FFFFFF; // 128 Mb
	public static void main(String[] args) throws Exception {  
//		String path="E:\\Program Files\\easyMule\\Incoming\\FEI\\[刺客信条：兄弟会].Assassins.Creed.Brotherhood-SKIDROW.iso";
//		long time=System.currentTimeMillis();
//		RandomAccessFile raf=new RandomAccessFile(path,"rw");
//		FileChannel in = raf.getChannel();
//		FileOutputStream fos=new FileOutputStream("D:\\aa.iso");
//		FileChannel out=fos.getChannel();
//		int begin=0;
//		if(raf.length()<length2){
//			MappedByteBuffer reader=in.map(FileChannel.MapMode.READ_WRITE, 0, raf.length()); 
//			reader.rewind();
//			out.write(reader);
//		}else{
//			int times=(int) (raf.length()/length2+1);
//			MappedByteBuffer reader;
//			for(int i=0;i<times;i++){
//				reader=in.map(FileChannel.MapMode.READ_WRITE, begin,length2);
//				reader.rewind();
//				out.write(reader);
//				begin=begin+length2+1;
//			}
//		}
		
		
		
//		File file=new File("E:\\Program Files\\easyMule\\Incoming\\FEI\\[刺客信条：兄弟会].Assassins.Creed.Brotherhood-SKIDROW.iso");
//		FileInputStream in = new FileInputStream(file); 
//		FileChannel ch = in.getChannel();
//		MappedByteBuffer byteBuffer = ch.map(FileChannel.MapMode.READ_WRITE, 0, file.length()); 
//		byteBuffer.rewind();
//		FileOutputStream fos=new FileOutputStream("D:\\aa.iso");
//		fos.getChannel().write(byteBuffer);
//		fos.getChannel().close();
//		fos.close();
//		ch.close();
//		in.close();
		//System.out.println((System.currentTimeMillis()-time)/1000);
		ByteBuffer byteBuffer =ByteBuffer.allocate(8);
		long a=1111111137;
		byteBuffer.putLong(a);
		
		//byteBuffer.putInt(5);
	}
	
}
