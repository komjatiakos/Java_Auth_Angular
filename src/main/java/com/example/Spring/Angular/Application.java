package com.example.Spring.Angular;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@SpringBootApplication
@Controller
public class Application {
    @GetMapping("/user")
    @ResponseBody
    public Principal user(Principal user) {
        return user;
    }

    @GetMapping("/resource")
    @ResponseBody
    public Map<String, Object> home() {
        Map<String, Object> model = new HashMap<String, Object>();
        model.put("id", UUID.randomUUID().toString());
        model.put("content", "Hello World");
        return model;
    }

    @GetMapping(value = "/{path:[^\\.]*}")
    public String redirect() {
        return "forward:/";
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        String encodedPassword = passwordEncoder.encode("password");

        UserDetails user = User.withUsername("user")
            .password(encodedPassword)
            .roles("USER")
            .build();
        
        return new InMemoryUserDetailsManager(user);
    }
}

/*
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfiguration {
    
    public void configure(WebSecurity web) throws Exception {
    	.antMatchers("/index.html", "/", "/home", "/login").permitAll()
    }
    
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .httpBasic()
                .and()
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
}*/