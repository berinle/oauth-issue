package com.example;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
  private JwtHelper jwtHelper;

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Before
  public void setUp() throws Exception {
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
  }

  @Test
  public void basicGet() throws Exception {
    mockMvc.perform(get("/hi").with(authHelper.addBearerToken("test", "ROLE_USER"))
        .accept(MediaType.APPLICATION_JSON_UTF8))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(content().string("hello"));
  }

  @Test
  public void basicGet_withJwt() throws Exception {
    mockMvc.perform(get("/hi").with(jwtHelper.injectValidBearerToken())
        .accept(MediaType.APPLICATION_JSON_UTF8))
        .andDo(print())
        .andExpect(status().isOk())
        .andExpect(content().string("hello"));
  }
}

/*@Component
class JwtRequestPostProcessor implements RequestPostProcessor {

  @Override
  public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
    String jwt = Jwts.builder()
        .claim("scope", Arrays.asList("read", "write", "junk"))
        .claim("client_id", "myclient")
        .signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encode("foo".getBytes()))
        .compact();

    System.out.println(">>>>>>jwt = " + jwt);
    request.addHeader("Authorization", "Bearer " + jwt);
    return request;
  }
}*/


@Component
class JwtHelper {
  @Autowired
  AuthorizationServerTokenServices tokenServices;

  RequestPostProcessor injectValidBearerToken() {
    return req -> {
      String jwt = Jwts.builder()
          .claim("client_id", "myclient")
          .claim("scope", Arrays.asList("read", "write"))
          .signWith(SignatureAlgorithm.HS256, Base64.encode("secret".getBytes()))
          .compact();
      req.addHeader("Authorization", "Bearer " + jwt);
      return req;
    };
  }
}


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
