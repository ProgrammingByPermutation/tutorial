package com.nullinside.webserviceapi.authentication;

import com.nullinside.webserviceapi.repositories.UsersRepository;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

/**
 * The provider handling username and password authentication.
 */
@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {
    /**
     * The user database table.
     */
    private final UsersRepository usersRepository;

    /**
     * Instantiates a new instance of the class.
     *
     * @param usersRepository The user database table.
     */
    public UsernamePasswordAuthenticationProvider(UsersRepository usersRepository) {
        this.usersRepository = usersRepository;
    }

    /**
     * Performs authentication with the same contract as AuthenticationManager.authenticate(Authentication).
     *
     * @param authentication The authentication request object.
     * @return A fully authenticated object including credentials. May return null if the AuthenticationProvider is unable to support authentication of the passed Authentication object. In such a case, the next AuthenticationProvider that supports the presented Authentication class will be tried.
     * @throws AuthenticationException if authentication fails.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = authentication.getName();
        Object passwordObj = authentication.getCredentials();
        if (null == passwordObj) {
            return null;
        }

        String password = passwordObj.toString();
        Pair<Boolean, String> authenticated = AuthenticationUtilities.passwordsMatch(this.usersRepository, email, password);

        if (authenticated.getKey()) {
            return new UsernamePasswordAuthenticationToken(email, authenticated.getValue(), new ArrayList<>());
        } else {
            return null;
        }
    }

    /**
     * Returns true if this AuthenticationProvider supports the indicated Authentication object.
     * Returning true does not guarantee an AuthenticationProvider will be able to authenticate the presented instance of the Authentication class. It simply indicates it can support closer evaluation of it. An AuthenticationProvider can still return null from the authenticate(Authentication) method to indicate another AuthenticationProvider should be tried.
     * Selection of an AuthenticationProvider capable of performing authentication is conducted at runtime the ProviderManager.
     *
     * @param authentication Not documented by Spring.
     * @return true if the implementation can more closely evaluate the Authentication class presented.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
