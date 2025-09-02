# Moqui SSO Component

Moqui Component for SSO authentication using pac4j.

To install run (with moqui-framework):

    $ ./gradlew getComponent -Pcomponent=moqui-sso


解决方案
1. 修复 Keycloak 配置（方式 1：Keycloak + OIDC + JWT）
步骤 1：启动 Keycloak（新端口 8082）

使用 Docker（推荐）：
bashdocker run -p 8082:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.0.0 start-dev

映射 8082（外部）到容器内部的 8080。
默认管理员：admin/admin。


验证 Keycloak 运行：
bashcurl http://localhost:8082
应返回 Keycloak 的欢迎页面或登录界面。
验证端点：
bashcurl http://localhost:8082/realms/master/.well-known/openid-configuration
预期返回：
json{
  "issuer": "http://localhost:8082/realms/master",
  "authorization_endpoint": "http://localhost:8082/realms/master/protocol/openid-connect/auth",
  "token_endpoint": "http://localhost:8082/realms/master/protocol/openid-connect/token",
  ...
}


步骤 2：配置 Keycloak

访问管理界面：http://localhost:8082/admin，登录（admin/admin）。
创建 Realm：

点击“Master”下拉菜单 > “Create Realm”。
名称：demo，保存。


创建客户端：

在 demo realm，点击“Clients” > “Create client”。
设置：

Client type：OpenID Connect
Client ID：moqui-client
Client authentication：启用（confidential）
Valid redirect URIs：http://localhost:8080/sso/callback


保存后，进入“Credentials”标签，复制 Client secret（如 abc123-your-actual-secret）。


配置 Scope：

在“Client scopes” > moqui-client-dedicated，确保包含 openid、profile、email.



步骤 3：更新 MoquiConf.xml

修改：
xml<moqui>
    <component name="moqui-sso" location="component/moqui-sso"/>
    <sso>
        <client name="Keycloak-OIDC" type="oidc" auth-flow-id="TEST_SSO"
                clientId="moqui-client"
                clientSecret="abc123-your-actual-secret"
                discoveryUri="http://localhost:8082/realms/demo/.well-known/openid-configuration"
                callbackUrl="http://localhost:8080/sso/callback"
                scope="openid profile email"
                clientAuthenticationMethod="client_secret_post"/>
    </sso>
    <webapp name="webroot" http-port="8080" https-enabled="false" token-sign-key=""/>
</moqui>

替换 clientSecret。
更新 discoveryUri 为 8082。
禁用 token-sign-key 避免 qz-private-key.pem 错误。



步骤 4：启用调试日志

在 log4j2.xml：
xml<Logger name="org.moqui.sso" level="debug"/>
<Logger name="org.pac4j" level="debug"/>

重启 Moqui：
bash./gradlew run

检查日志：
textLoading SSO configuration for client [Keycloak-OIDC]
Initializing pac4j OIDC client


步骤 5：解决 Ambiguous method overloading

修改 AuthenticationFlow.groovy：
groovystatic void loginUser(ExecutionContext ec) {
    String authFlowId = ec.context.get("authFlowId") as String
    ec.logger.info("Received authFlowId: ${authFlowId}")
    Client client = new AuthenticationClientFactory(ec).build(authFlowId)
    ec.logger.info("Client: ${client}")
    if (client == null) {
        ec.logger.error("No client found for authFlowId: ${authFlowId}")
    }
    Config config = new Config(callbackUrl, client)
    ...
}

测试：http://localhost:8080/sso/login?authFlowId=TEST_SSO

步骤 6：解决 Base64 错误

清理会话：
bashcurl -X POST http://localhost:8080/rest/s/logout
或清除 moqui.session.token cookie。
添加 token 配置：
xml<webapp name="webroot" ... session-token-issuer="http://localhost:8082/realms/demo" session-token-audience="moqui-client"/>


步骤 7：测试 JWT

访问 http://localhost:8080/sso/login?authFlowId=TEST_SSO。
登录后，获取 Access Token：
bashcurl -X POST http://localhost:8082/realms/demo/protocol/openid-connect/token \
  -d "client_id=moqui-client" \
  -d "client_secret=abc123-your-actual-secret" \
  -d "grant_type=client_credentials"

使用 JWT：
bashcurl -H "Authorization: Bearer <access_token>" http://localhost:8080/rest/s/...


2. 独立 JWT 支持（方式 2：无需 Keycloak）
如果你希望避免部署 Keycloak，moqui-sso 可以通过自定义服务直接验证 JWT。
步骤 1：移除 Keycloak 配置

修改 MoquiConf.xml：
xml<moqui>
    <component name="moqui-sso" location="component/moqui-sso"/>
    <webapp name="webroot" http-port="8080" https-enabled="false"
            session-token-issuer="moqui" session-token-audience="moqui-client"/>
</moqui>


步骤 2：添加 JWT 服务

创建 component/moqui-sso/service/JwtAuthServices.xml：
xml<service verb="authenticate" noun="JwtToken">
    <in-parameters>
        <parameter name="token" required="true"/>
    </in-parameters>
    <actions>
        <script>
            import io.jsonwebtoken.*
            String token = context.token
            try {
                Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey('your-secret-key'.bytes)
                    .requireIssuer('moqui')
                    .requireAudience('moqui-client')
                    .build()
                    .parseClaimsJws(token)
                String username = claims.body.sub
                ec.user.internalLoginUser(username)
                return [authenticated: true, username: username]
            } catch (JwtException e) {
                ec.logger.error("JWT validation failed: ${e.message}")
                return [authenticated: false]
            }
        </script>
    </actions>
</service>

添加依赖（build.gradle）：
groovyimplementation 'io.jsonwebtoken:jjwt-api:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'


步骤 3：生成测试 JWT

使用 Node.js：
bashnpm install jsonwebtoken
javascriptconst jwt = require('jsonwebtoken');
const token = jwt.sign({ sub: 'testuser' }, 'your-secret-key', { issuer: 'moqui', audience: 'moqui-client', expiresIn: '1h' });
console.log(token);

复制 JWT（eyJ...）。

步骤 4：测试 JWT

调用服务：
bashcurl -X POST http://localhost:8080/rest/s/authenticate/JwtToken -d '{"token": "eyJ..."}'

访问 API：
bashcurl -H "Authorization: Bearer eyJ..." http://localhost:8080/rest/s/...


步骤 5：解决错误

Base64 错误：清理会话（如上）。
签名密钥：确保 token-sign-key="" 或提供 qz-private-key.pem：
bashopenssl genrsa -out qz-private-key.pem 2048


3. 推荐方式

方式 1（Keycloak）：适合需要完整 SSO（用户管理、登录界面）。需要部署 Keycloak，但支持标准 OIDC 和 JWT。
方式 2（独立 JWT）：适合快速验证 JWT，环境简单，但需开发 JWT 验证逻辑，缺乏 SSO 功能。


回答你的问题

是否支持 JWT：是的，moqui-sso 支持：

方式 1：通过 OIDC（Keycloak）返回 JWT（ID Token 和 Access Token）。
方式 2：自定义服务直接验证 JWT。


复杂性：

方式 1 需要 Keycloak，配置稍复杂但功能全面。
方式 2 简单，无需额外部署，但需开发代码。


建议：如果你只是验证 JWT 支持，推荐方式 2。如果需要生产级 SSO，选择方式 1。
