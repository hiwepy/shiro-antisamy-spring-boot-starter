package org.apache.shiro.spring.boot.antisamy.web.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.spring.boot.antisamy.web.servlet.http.HttpServletEscapeHtml4RequestWrapper;
import org.apache.shiro.web.filter.AccessControlFilter;
 

/**
 * 基于StringEscapeUtils.escapeHtml4()方法的XSS(Cross Site Scripting)，即跨站脚本攻击请求过滤
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class HttpServletRequestEscapeHtml4Filter extends AccessControlFilter {
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		return true;
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return true;
	}
	
	@Override
	public void executeChain(ServletRequest request, ServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		
		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			throw new ServletException( "just supports HTTP requests");
		}
		
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		//执行下个责任链：将封装后的请求传递下去
		chain.doFilter(new HttpServletEscapeHtml4RequestWrapper(httpRequest), httpResponse);
		
	}

}
