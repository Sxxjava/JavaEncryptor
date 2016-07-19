package com.szhynet.lib.encryptor;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *MD5加密的工具类.
 */
public class Encryptor {


    /**
     * MD5 摘要，使用系统缺省字符集编码
     * @param input 加密的内容
     * @return
     */
    public static String MD5(String input) {
        return MD5(input, Charset.defaultCharset());
    }

    /**
     * MD5 摘要，使用系统缺省字符集编码
     * @param input 加密的内容
     * @return
     */
    public static String MD5(String input,boolean isDisturb) {
        return new StringBuffer(MD5(input, Charset.defaultCharset())).reverse().toString();
    }

    /**
     * MD5 摘要
     * @param input 加密的内容
     * @param charset 加密使用的字符集
     * @return
     */
    public static String MD5(String input, String charset) {
        return MD5(input, Charset.forName(charset));
    }

    /**
     * MD5 摘要，使用系统缺省字符集编码
     *
     * @param input 加密的内容
     * @param number 加密的次数
     * @return
     */
    public static String MD5(String input,int number) {
        if (number<1)
            return MD5(input, Charset.defaultCharset());
        String temp=input;
        for (int x=0;x<=number;x++){
            temp=MD5(temp, Charset.defaultCharset());
        }
        return temp;
    }

    /**
     * MD5 摘要
     * @param input 加密的内容
     * @param charset 使用的字符集
     * @param number 加密次数
     * @return
     */
    public static String MD5(String input, String charset,int number) {
        if (number<1)
            return MD5(input, Charset.defaultCharset());
        String temp=input;
        for (int x=0;x<=number;x++){
            temp=MD5(temp, Charset.forName(charset));
        }
        return temp;
    }

    /**
     * MD5 摘要，使用系统缺省字符集编码
     *
     * @param input 加密的内容
     * @param number 加密的次数
     * @return
     */
    public static String MD5(String input,int number,boolean isDisturb) {
        if (number<2)
            return MD5(input, isDisturb);
        String temp=input;
        StringBuffer buffer=new StringBuffer();
        for (int x=0;x<=number;x++){
            if (isDisturb) {
                temp = buffer.append(MD5(temp, Charset.defaultCharset())).reverse().toString();
                buffer.delete(0, buffer.length());
            }else{
                temp=MD5(temp, Charset.defaultCharset());
            }
        }
        return temp;
    }

    /**
     * MD5 摘要
     * @param input 加密的内容
     * @param charset 使用的字符集
     * @param number 加密次数
     * @return
     */
    public static String MD5(String input, String charset,int number,boolean isDisturb) {
        if (number<1)
            return MD5(input, Charset.forName(charset));
        String temp=input;
        StringBuffer buffer=new StringBuffer();
        for (int x=0;x<=number;x++){
            if (isDisturb) {
                temp = buffer.append(MD5(temp, Charset.forName(charset))).reverse().toString();
                buffer.delete(0, buffer.length());
            }else{
                temp=MD5(temp, Charset.forName(charset));
            }
        }
        return temp;
    }

    /**
     * MD5 摘要
     * 
     * @param input
     * @param charset
     * @return
     */
    public static String MD5(String input, Charset charset) {
        MessageDigest md = null;

        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        //去掉编码支持.
        md.update(input.getBytes());

        char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'a', 'b', 'c', 'd', 'e', 'f' };
        byte tmp[] = md.digest();
        char str[] = new char[16 * 2];

        int k = 0;
        for (int i = 0; i < 16; i++) {
            byte byte0 = tmp[i];
            str[k++] = hexDigits[byte0 >>> 4 & 0xf];
            str[k++] = hexDigits[byte0 & 0xf];
        }

        String result = new String(str);

        //转换为大写
        return result;//result.toUpperCase(Locale.CHINA)
    }

    public static String getSecurityKey(String md5){
        if (md5==null) {
            return null;
        }
        if (md5.length()!=32) {
            return null;
        }
        String temp=null;
        StringBuffer buffer=new StringBuffer();
        return buffer.append(md5.substring(0, 8)).reverse().append(md5.substring(24, md5.length())).reverse().reverse().toString();
    }
    public static String getSecurityIv(String time){
        if (time==null) {
            return null;
        }
        if (time.length()!=13) {
            return null;
        }
        StringBuffer buffer=new StringBuffer(time).reverse();
        return buffer.append(time.substring(10, 13)).reverse().toString();
    }
    /*
     * 加密用的Key 可以用26个字母和数字组成 此处使用AES-128-CBC加密模式，key需要为16位。
     */
    private static String sKey = "sxxKkIiD9979jour";
    private static String ivParameter = "0369025801470395";

    public static String encryptAES(String encData ,String secretKey,String vector) throws Exception {

        if(secretKey == null) {
            return null;
        }
        if(secretKey.length() != 16) {
            return null;
        }
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] raw = secretKey.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        IvParameterSpec iv = new IvParameterSpec(vector.getBytes());// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(encData.getBytes("utf-8"));
        return new BASE64Encoder().encode(encrypted);// 此处使用BASE64做转码。
    }


    // 加密
    public static String encryptAES(String sSrc) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] raw = sKey.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivParameter.getBytes());// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(sSrc.getBytes("utf-8"));
        return new BASE64Encoder().encode(encrypted);// 此处使用BASE64做转码。
    }

    // 解密
    public static String decryptAES(String sSrc) {
        try {
            byte[] raw = sKey.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(ivParameter.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] encrypted1 = new BASE64Decoder().decodeBuffer(sSrc);// 先用base64解密
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original, "utf-8");
            return originalString;
        } catch (Exception ex) {
            return null;
        }
    }

    public static String decryptAES(String sSrc,String key,String ivs) {
        try {
            byte[] raw = key.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(ivs.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] encrypted1 = new BASE64Decoder().decodeBuffer(sSrc);// 先用base64解密
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original, "utf-8");
            return originalString;
        } catch (Exception ex) {
            return null;
        }
    }

    public static String encodeBytes(byte[] bytes) {
        StringBuffer strBuf = new StringBuffer();

        for (int i = 0; i < bytes.length; i++) {
            strBuf.append((char) (((bytes[i] >> 4) & 0xF) + ((int) 'a')));
            strBuf.append((char) (((bytes[i]) & 0xF) + ((int) 'a')));
        }

        return strBuf.toString();
    }

    /**
     * 获取随机生成的web端的sign值
     * @param sessionId
     * @return
     */
    public static String getWebSignString(String sessionId){
        String temp=MD5(sessionId,"UTF-8",30);
        temp=temp+MD5(System.currentTimeMillis()+"","UTF-8",32);
        return MD5(temp,"UTF-8",36);
    }
}
