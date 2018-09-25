package org.apache.shiro.spring.boot.antisamy.web.servlet.http;

import java.util.Enumeration;

import org.apache.shiro.spring.boot.antisamy.cache.AntiSamyWrapper;
import org.apache.shiro.spring.boot.antisamy.utils.AntiSamyScanUtils;

public class AntiSamyEnumeration implements Enumeration<String> {
	
	/**AntiSamyProxy对象*/
	private AntiSamyWrapper antiSamyProxy = null;
	/**原始Header*/
	private Enumeration<String> headers;
	
	public AntiSamyEnumeration(Enumeration<String> headers, AntiSamyWrapper antiSamyProxy){
		this.antiSamyProxy = antiSamyProxy;
		this.headers = headers;
	}
	
	@Override
	public boolean hasMoreElements() {
		return headers.hasMoreElements();
	}

	@Override
	public String nextElement() {
		return AntiSamyScanUtils.xssClean( antiSamyProxy, headers.nextElement());
	}

}
