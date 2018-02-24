package main.org.zcy.demo;

import com.auth0.jwt.interfaces.Claim;

import java.util.Map;

public class JwtTokenDemo {
    public static void main(String[] args) throws Exception {
        String token =JwtToken.createToken();

        System.out.println("Token"+token);

        Map<String,Claim> claims=JwtToken.verifyToken(token);
        System.out.println(claims.get("name").asString());
        System.out.println(claims.get("age").asString());
        System.out.println(claims.get("org").asString());
    }
}
