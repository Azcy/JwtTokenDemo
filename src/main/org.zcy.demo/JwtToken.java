package main.org.zcy.demo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class JwtToken {
    /**
     * 公用秘钥-保存在服务的，客户端是不会知道秘钥的，以防被攻击
     */
    public static String SECRET="ROOKIE";


    /**
     * 生成token
     * @return
     * @throws Exception
     */
    public static String createToken() throws Exception {
        //签发时间
        Date iatDate=new Date();

        //过期时间- 1分钟过期
        Calendar nowTime = Calendar.getInstance();

        //获取下一分钟后的时间
        nowTime.add(Calendar.MINUTE,1);

        //过期时间
        Date expiresDate=nowTime.getTime();

        /**
         * header
         * 封装jwt的头部信息，主要两部分
         * 1、声明类型，这里是jwt
         * 2、声明加密的算法同城直接使用 HMAC SHA256
         */
        Map<String,Object> map=new HashMap<String, Object>();
        map.put("alg","HS256");
        map.put("typ","JWT");

        String token= JWT.create()
                .withHeader(map)//header
                .withClaim("name","zcy")//payload
                .withClaim("age","24")
                .withClaim("org","java")
                .withExpiresAt(expiresDate)//设置过期时间，过期时间大于签发时间
                .withIssuedAt(iatDate)//设置签发时间
                .sign(Algorithm.HMAC256(SECRET));//加密

        return token;

    }


    /**
     * 解密Token
     * @param token
     * @return
     * @throws Exception
     */
    public static Map<String,Claim> verifyToken(String token) throws Exception{
        JWTVerifier verifier=JWT.require(Algorithm.HMAC256(SECRET)).build();

        DecodedJWT jwt=null;
        try {
            jwt=verifier.verify(token);
        }catch (Exception e){
            throw new RuntimeException("登录凭证已过期，请重新登录");
        }

        return jwt.getClaims();

    }

}
