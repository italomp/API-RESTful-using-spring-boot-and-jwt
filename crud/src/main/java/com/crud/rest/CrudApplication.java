package com.crud.rest;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

/**
 * This is the main class of the project, because it has 
 * springBootApplication annotation. That's why it
 * is the responsible class for uploading the spring server.
 */
@SpringBootApplication
@ComponentScan("com.crud")
public class CrudApplication {

	/**
	 * This static method start the spring server.
	 * @param args: argument array.
	 */
	public static void main(String[] args) {
		SpringApplication.run(CrudApplication.class, args);
	}
	
	/**
	 * This method is responsible for filtering tokens for 
	 * private routes. And here are noted all the private routes.
	 * The '*' at the end of the route indicates that all the routes
	 * beginning with "/v1/product/private/" are being passed as a 
	 * parameter to the addUrlPatterns method.
	 */
	@Bean
	public FilterRegistrationBean filterJwt(){
		FilterRegistrationBean filter = new FilterRegistrationBean();
		filter.setFilter(new TokenFilter());
		filter.addUrlPatterns("/v1/product/private/*");
		return filter;
	}

	    
	@Configuration
	public class WebConfig implements WebMvcConfigurer {
		 @Override
         public void addCorsMappings(CorsRegistry registry) {
             registry.addMapping("/**")
             		.allowedOrigins("https://italomp.github.io") //this value can't be "*", because allowCredentials(true).
             		.allowedMethods("PUT", "DELETE","POST","GET", "OPTIONS")
             		.allowedHeaders("Content-Type", "Authorization", "Referrer-Plicy")
             		.allowCredentials(true)
             		.maxAge(3600);
         }
	}    
	    
	    
}
