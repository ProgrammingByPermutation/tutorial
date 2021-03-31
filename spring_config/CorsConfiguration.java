package com.nullinside.webserviceapi;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.ArrayList;

/**
 * Handles the configuration of CORS requests.
 */
@Configuration
public class CorsConfiguration {
    /**
     * The bean that passes the CORS configuration to Spring.
     *
     * @return The CORS configuration.
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            /**
             * Adds the CORS settings to the CORS Registry.
             * @param registry The CORS registry.
             */
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                var allowedDevOrigins = new String[]{
                        "localhost",
                        "127.0.0.1",
                        "localhost:3000",
                        "127.0.0.1:3000",
                        "localhost:4200",
                        "127.0.0.1:4200",
                        "localhost:8888",
                        "127.0.0.1:8888",
                };

                var parsed = new ArrayList<String>();
                for (var origin : allowedDevOrigins) {
                    parsed.add("http://" + origin);
                    parsed.add("https://" + origin);
                    parsed.add("http://www." + origin);
                    parsed.add("https://www." + origin);
                }

                parsed.add("https://www.nullinside.com");
                parsed.add("https://nullinside.com");

                registry.addMapping("/**")
                        .allowedOrigins(parsed.toArray(String[]::new))
                        .allowCredentials(true);
            }
        };
    }
}
