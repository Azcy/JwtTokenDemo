### JWT的构成
第一部分我们称它为头部（header),第二部分我们称其为载荷（payload)，第三部分是签证（signature)。

header

jwt的头部承载两部分信息：

声明类型，这里是jwt

声明加密的算法 通常直接使用 HMAC SHA256

完整的头部就像下面这样的JSON：

{

"typ": "JWT",

"alg": "HS256"

}

然后将头部进行base64加密（该加密是可以对称解密的),构成了第一部分：

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

playload

载荷就是存放有效信息的地方。这个名字像是特指飞机上承载的货品，这些有效信息包含三个部分

标准中注册的声明

公共的声明

私有的声明

标准中注册的声明 (建议但不强制使用) ：

iss: jwt签发者

sub: jwt所面向的用户

aud: 接收jwt的一方

exp: jwt的过期时间，这个过期时间必须要大于签发时间

nbf: 定义在什么时间之前，该jwt都是不可用的.

iat: jwt的签发时间

jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。

公共的声明 ：

公共的声明可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息.但不建议添加敏感信息，因为该部分在客户端可解密.

私有的声明 ：

私有声明是提供者和消费者所共同定义的声明，一般不建议存放敏感信息，因为base64是对称解密的，意味着该部分信息可以归类为明文信息。

定义一个payload：

{

"name":"Free码农",

"age":"28",

"org":"今日头条"

}

然后将其进行base64加密，得到Jwt的第二部分：

eyJvcmciOiLku4rml6XlpLTmnaEiLCJuYW1lIjoiRnJlZeeggeWGnCIsImV4cCI6MTUxNDM1NjEwMywiaWF0IjoxNTE0MzU2MDQzLCJhZ2UiOiIyOCJ9

signature

jwt的第三部分是一个签证信息，这个签证信息由三部分组成：

header (base64后的)

payload (base64后的)

secret

这个部分需要base64加密后的header和base64加密后的payload使用.连接组成的字符串，然后通过header中声明的加密方式进行加盐secret组合加密，然后就构成了jwt的第三部分：

49UF72vSkj-sA4aHHiYN5eoZ9Nb4w5Vb45PsLF7x_NY

密钥secret是保存在服务端的，服务端会根据这个密钥进行生成token和验证，所以需要保护好。