package com.nullinside.webserviceapi.authentication;

import antlr.StringUtils;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * An authentication filter for handling both basic and bearer authentication.
 */
public class CustomAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    /**
     * Instantiates a new instance of the class.
     *
     * @param requiresAuth The request mapper for forwarding the request after authentication.
     */
    public CustomAuthenticationFilter(final RequestMatcher requiresAuth) {
        super(requiresAuth);
    }

    /**
     * Performs actual authentication.
     *
     * @param httpServletRequest  The request from which to extract parameters and perform the authentication
     * @param httpServletResponse The response, which may be needed if the implementation has to do a redirect as part of a multi-stage authentication process (such as OpenID).
     * @return The authenticated user token, or null if authentication is incomplete.
     * @throws AuthenticationException if authentication fails.
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException {
        String header = httpServletRequest.getHeader(AUTHORIZATION);
        if (null == header) {
            throw new AuthenticationCredentialsNotFoundException("Authorization header was not provided.");
        }

        Authentication requestAuthentication = null;
        if (header.contains("Bearer")) {
            String token = StringUtils.stripFront(header, "Bearer").strip();
            requestAuthentication = new RememberMeAuthenticationToken(token, token, null);
        } else if (header.contains("Basic")) {
            String base64 = StringUtils.stripFront(header, "Basic").strip();
            String usernamePassword = new String(Base64.getDecoder().decode(base64));
            int index = usernamePassword.indexOf(':');
            if (-1 == index) {
                throw new AuthenticationCredentialsNotFoundException("Authorization header was not provided.");
            }

            String username = usernamePassword.substring(0, index);
            String password = usernamePassword.substring(index + 1);
            requestAuthentication = new UsernamePasswordAuthenticationToken(username, password);
        } else {
            throw new ProviderNotFoundException("Authorization header did not contain a valid mechanism.");
        }

        return getAuthenticationManager().authenticate(requestAuthentication);
    }

    /**
     * Default behaviour for successful authentication.
     *
     * @param request    The request.
     * @param response   The response.
     * @param chain      The filter chain for the request.
     * @param authResult The object returned from the attemptAuthentication method.
     * @throws IOException      Not documented by Spring.
     * @throws ServletException Not documented by Spring.
     */
    @Override
    protected void successfulAuthentication(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain, final Authentication authResult) throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(authResult);
        chain.doFilter(request, response);
    }
}
