package com.crud.rest;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.filter.GenericFilterBean;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

/** 
 * This class is responsible for filtering the received tokens
 * in the requests.
 * @author Italo Modesto
 */
public class TokenFilter extends GenericFilterBean{

	/**
	 * This method applies a filter on tokens to verify if it's valid.
	 * 
	 * Firstly, this method converts ServeletRequest to HttpServlerReques 
	 * to be able to access its authorization attribute;
	 * 
	 * then this method extracts the authorization attribute from 
	 * the request and check if the attribute is null or badly formatted (in
	 * these cases, exceptions will be throws);
	 * 
	 * Finally, The token is extracted from the request and unpacked for it
	 * can be passed as parameter to the filter chain.
	 * 
	 * The filter chain (in this case) call the resource requested.
	 * 
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		String auth = extractAuth(req);
		System.out.println(auth);
		if(auth == null || !auth.startsWith("Bearer ")) {
			throw new ServletException("Token inexistente ou mal formatado");
		}
		String token = auth.substring(7);
		try {
			Jwts.parser().setSigningKey("caneca").parseClaimsJws(token).getBody();
		}catch(SignatureException e) {
			throw new ServletException("Token inválido ou expirado");
		}
		chain.doFilter(request, response);
	}
	
	public String extractAuth(HttpServletRequest request) {
		String auth = request.getHeader("Authorization");
		System.out.println("header extraído da request " + auth); //remover esta linh@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
		return auth; //getHeaders retorna um enumeration; nextElement() chama o próximo elemento da estrutura.
	}

}