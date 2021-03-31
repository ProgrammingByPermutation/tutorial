package com.nullinside.webserviceapi;

import com.nullinside.webserviceapi.authentication.CustomAuthenticationFilter;
import com.nullinside.webserviceapi.authentication.TokenAuthenticationProvider;
import com.nullinside.webserviceapi.authentication.UsernamePasswordAuthenticationProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * The main entry point of the application.
 */
@SpringBootApplication
public class WebServiceApiApplication {
    /**
     * Boilerplate code to run Spring.
     *
     * @param args The application arguments passed in.
     */
    public static void main(String[] args) {
        SpringApplication.run(WebServiceApiApplication.class, args);
    }

    /**
     * The configuration of the Spring application.
     */
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
        /**
         * The list of URLs that need to be protected for authentication. The **NEEDS** to
         * include the list of things NOT to include for authentication protection as a NegatedRequestMatcher.
         * The list should match the {@link WebSecurityConfig#configure(WebSecurity)}'s return values.
         */
        private static final RequestMatcher PROTECTED_URLS = new AndRequestMatcher(
                new AntPathRequestMatcher("/**"),
                new NegatedRequestMatcher(
                        new AntPathRequestMatcher("/api/**/auth**/**")
                ),
                new NegatedRequestMatcher(
                        new AntPathRequestMatcher("/error")
                ),
                new NegatedRequestMatcher(
                        new AntPathRequestMatcher("/api/**/apps")
                ),
                new NegatedRequestMatcher(
                        new AntPathRequestMatcher("/**", HttpMethod.OPTIONS.toString())
                )
        );
        /**
         * The authenticator that handles "Authentication: Basic" authentication.
         */
        UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;
        /**
         * The authenticator that handles "Authentication: Bearer" authentication.
         */
        TokenAuthenticationProvider tokenAuthenticationProvider;

        /**
         * Initializes a new instance of the WebSecurityConfig class.
         *
         * @param usernamePasswordAuthenticationProvider The authenticator that handles "Authentication: Basic" authentication.
         * @param tokenAuthenticationProvider            The authenticator that handles "Authentication: Bearer" authentication.
         */
        public WebSecurityConfig(UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider, TokenAuthenticationProvider tokenAuthenticationProvider) {
            super();
            this.usernamePasswordAuthenticationProvider = usernamePasswordAuthenticationProvider;
            this.tokenAuthenticationProvider = tokenAuthenticationProvider;
        }

        /**
         * Injects the custom authentication handles into Spring.
         *
         * @param auth The authentication manager from Spring to add authentication handlers into.
         */
        @Override
        protected void configure(AuthenticationManagerBuilder auth) {
            auth.authenticationProvider(usernamePasswordAuthenticationProvider);
            auth.authenticationProvider(tokenAuthenticationProvider);
        }

        /***
         * Specifies the list of URLs to ignore for authentication. Should match the
         * {@link WebSecurityConfig#PROTECTED_URLS} list.
         * @param web The Spring web security instance to add our URLs to ignore.
         */
        @Override
        public void configure(WebSecurity web) {
            web.ignoring()
                    .antMatchers("/api/**/auth**/**")
                    .antMatchers("/error")
                    .antMatchers("/api/**/apps")
                    .antMatchers(HttpMethod.OPTIONS, "/**");
        }

        /**
         * Specifies the configuration chain for how to handle requests.
         *
         * @param http The Spring module used for security configuration.
         * @throws Exception The exception from Spring if the authentication manager fails. Spring does not document why this is thrown.
         */
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .addFilterBefore(getCustomAuthenticationFilter(), AnonymousAuthenticationFilter.class)
                    .authorizeRequests()
                    .antMatchers("/api/**/tv_guide/**").hasAnyAuthority("tv_guide")
                    .anyRequest().authenticated()
                    .and()
                    .httpBasic().disable()
                    .csrf().disable();
        }

        /**
         * Creates a new instance of our custom authentication manager.
         *
         * @return A new instance of the custom authentication manager.
         * @throws Exception The exception from Spring if the authentication manager fails. Spring does not document why this is thrown.
         */
        @Bean
        CustomAuthenticationFilter getCustomAuthenticationFilter() throws Exception {
            final CustomAuthenticationFilter filter = new CustomAuthenticationFilter(PROTECTED_URLS);
            filter.setAuthenticationManager(authenticationManager());
            return filter;
        }
    }
}
