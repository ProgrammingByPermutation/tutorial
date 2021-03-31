package com.nullinside.webserviceapi.authentication;

import com.nullinside.webserviceapi.models.db.UsersEntity;
import com.nullinside.webserviceapi.repositories.UsersPermittedAppsRepository;
import com.nullinside.webserviceapi.repositories.UsersRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.util.ArrayList;

/**
 * The provider handling Bearer token based authentication.
 */
@Component
public class TokenAuthenticationProvider implements AuthenticationProvider {
    /**
     * The user database table.
     */
    private final UsersRepository usersRepository;
    /**
     * The user permitted apps database table.
     */
    private final UsersPermittedAppsRepository usersPermittedAppsRepository;

    /**
     * Instantiates a new instance of the class.
     *
     * @param usersRepository              The database user table.
     * @param usersPermittedAppsRepository The user permitted apps database table.
     */
    public TokenAuthenticationProvider(UsersRepository usersRepository, UsersPermittedAppsRepository usersPermittedAppsRepository) {
        this.usersRepository = usersRepository;
        this.usersPermittedAppsRepository = usersPermittedAppsRepository;
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
        UsersEntity user = this.usersRepository.findByToken(authentication.getPrincipal().toString());
        if (null == user) {
            return null;
        }

        if (user.getTokenExpiration().after(new Timestamp(System.currentTimeMillis()))) {
            // Grabbing the applications the user has access to.
            var permissions = this.usersPermittedAppsRepository.findAllByUserId(user.getId());
            var authorities = new ArrayList<GrantedAuthority>();
            for (var permission : permissions) {
                authorities.add(new SimpleGrantedAuthority(String.valueOf(permission.getApp().getName())));
            }

            return new RememberMeAuthenticationToken(authentication.getPrincipal().toString(), user.getEmail(), authorities);
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
        return authentication.equals(RememberMeAuthenticationToken.class);
    }
}
