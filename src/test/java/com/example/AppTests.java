package com.example;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.Base64;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;

//http://stackoverflow.com/questions/25764459/spring-boot-application-properties-value-not-populating
@RunWith(SpringRunner.class)

//mvc slice
//@WebMvcTest(FooController.class)
//@TestPropertySource("classpath:application.properties")

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AppTests {

  @Value("${jwt.signingKey}")
  private String signingKey;

  @Autowired
  private OAuthHelper authHelper;

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Before
  public void setUp() throws Exception {
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
  }

  @Test
  public void basicGet() throws Exception {
//    mockMvc.perform(get("/hi").with(new JwtRequestPostProcessor())
    mockMvc.perform(get("/hi").with(authHelper.addBearerToken("test", "ROLE_USER"))
        .accept(MediaType.APPLICATION_JSON_UTF8))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(content().string("hello"));
  }
}


/*@Configuration
@EnableAuthorizationServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
class TestAuthorizationServer extends AuthorizationServerConfigurerAdapter {
  @Autowired
  private AuthenticationManager authenticationManager;

//  @Autowired
//  private TokenStore tokenStore;

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients
        .inMemory()
        .withClient("myclient")
        .scopes("read", "write");
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    endpoints
        .authenticationManager(authenticationManager)
//        .tokenStore(tokenStore)
        .accessTokenConverter(accessTokenConverter());
  }

  @Bean
  public AccessTokenConverter accessTokenConverter() throws Exception {
    JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
    converter.setSigningKey("secret");
    converter.afterPropertiesSet();
    return converter;
  }

}*/

@Component
class JwtRequestPostProcessor implements RequestPostProcessor {

//  private final String signingKey;
//
//  JwtRequestPostProcessor(String signingKey) {
//    this.signingKey = signingKey;
//  }

  @Override
  public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
    String jwt = Jwts.builder()
        .claim("scope", Arrays.asList("read", "write", "junk"))
        .claim("client_id", "myclient")
//        .signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encode(signingKey.getBytes()))
        .signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encode("mykey".getBytes()))
        .compact();

    System.out.println(">>>>>>jwt = " + jwt);
    request.addHeader("Authorization", "Bearer " + jwt);
    return request;
  }
}

//@Configuration
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
//
//  @Override
//  protected MethodSecurityExpressionHandler createExpressionHandler() {
//    return new OAuth2MethodSecurityExpressionHandler();
//  }
//}

@Component
class OAuthHelper {

  @Autowired
  AuthorizationServerTokenServices tokenservice;

  public RequestPostProcessor addBearerToken(final String username, String... authorities) {
    return mockRequest -> {
      // Create OAuth2 token
      OAuth2Request oauth2Request = new OAuth2Request(null, "myclient", null, true, null, null, null, null, null);
      Authentication userauth = new TestingAuthenticationToken(username, null, authorities);
      OAuth2Authentication oauth2auth = new OAuth2Authentication(oauth2Request, userauth);
      OAuth2AccessToken token = tokenservice.createAccessToken(oauth2auth);

      // Set Authorization header to use Bearer
      mockRequest.addHeader("Authorization", "Bearer " + token.getValue());
      return mockRequest;
    };
  }
}
