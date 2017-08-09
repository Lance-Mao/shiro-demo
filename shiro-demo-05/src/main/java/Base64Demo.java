import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.*;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.SimpleByteSource;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import java.security.Key;

public class Base64Demo {

    @Test
    public void test() {
        String str = "hello";
        String base64Encoded = Base64.encodeToString(str.getBytes());
        String str2 = Base64.decodeToString(base64Encoded);
        Assert.assertEquals(str, str2);
        System.out.println(str2);
    }

    @Test
    public void test02() {
        String str = "hello";
        String base64Encoded = Hex.encodeToString(str.getBytes());
        String str2 = new String(Hex.decode(base64Encoded.getBytes()));
        Assert.assertEquals(str, str2);
        System.out.println(str2);
    }

    @Test
    public void testMD5() {
        String str = "hello";
        String salt = "123";
        String md5 = new Md5Hash(str, salt).toString();
        System.out.println(md5);
    }

    @Test
    public void testSHA256() {
        String str = "hello";
        String salt = "123";
        String sha1 = new Sha256Hash(str, salt).toString();
        System.out.println(sha1);
    }

    @Test
    public void testSimpleHash() {
        String str = "hello";
        String salt = "123";
        String simoleHash = new SimpleHash("SHA-1", str, salt).toString();
        System.out.println(simoleHash);
    }

    @Test
    public void testDefaultHashService() {
        DefaultHashService hashService = new DefaultHashService(); //默认算法SHA-215
        hashService.setHashAlgorithmName("SHA-512");
        hashService.setPrivateSalt(new SimpleByteSource("123")); //私盐,默认无
        hashService.setGeneratePublicSalt(true);
        hashService.setRandomNumberGenerator(new SecureRandomNumberGenerator());  //用于生成公盐，默认设置就是这个

        hashService.setHashIterations(1);  //生成Hash值的迭代次数
        HashRequest request = new HashRequest.Builder()
                .setAlgorithmName("MD5").setSource(ByteSource.Util.bytes("hello"))
                .setSalt(ByteSource.Util.bytes("123")).setIterations(2).build();
        String hex = hashService.computeHash(request).toHex();

        /**
         *
         1、首先创建一个DefaultHashService，默认使用SHA-512算法；
         2、可以通过hashAlgorithmName属性修改算法；
         3、可以通过privateSalt设置一个私盐，其在散列时自动与用户传入的公盐混合产生一个新盐；
         4、可以通过generatePublicSalt属性在用户没有传入公盐的情况下是否生成公盐；
         5、可以设置randomNumberGenerator用于生成公盐；
         6、可以设置hashIterations属性来修改默认加密迭代次数；
         7、需要构建一个HashRequest，传入算法、数据、公盐、迭代次数。
         */
    }

    @Test
    public void testSecureRandomNumberGenerator() {  //SecureRandomNumberGenerator用于生成一个随机数：
        SecureRandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();
        randomNumberGenerator.setSeed("123".getBytes());
        String hex = randomNumberGenerator.nextBytes().toHex();

        System.out.println(hex);
    }

    /**
     * 加密/解密
     */
    @Test
    public void testAesCipherService() {
        AesCipherService aesCipherService = new AesCipherService();
        aesCipherService.setKeySize(128);//设置key长度

        //生成key
        Key key = aesCipherService.generateNewKey();

        String text = "hello";

        //加密
        String encrptText = aesCipherService.encrypt(text.getBytes(), key.getEncoded()).toHex();
        //解密
        String text2 = new String(aesCipherService.decrypt(Hex.decode(encrptText), key.getEncoded()).getBytes());

        Assert.assertEquals(text, text2);

        System.out.println(text);
        System.out.println(encrptText);
        System.out.println(text2);
    }

    /**
     * Shiro提供了PasswordService及CredentialsMatcher用于提供加密密码及验证密码服务。
     */

}

