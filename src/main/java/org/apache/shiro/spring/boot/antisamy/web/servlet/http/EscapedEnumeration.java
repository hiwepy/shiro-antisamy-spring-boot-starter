package org.apache.shiro.spring.boot.antisamy.web.servlet.http;

import java.util.Enumeration;

import org.apache.commons.text.StringEscapeUtils;

public class EscapedEnumeration implements Enumeration<String> {

	private Enumeration<String> headers;
	
	public EscapedEnumeration(Enumeration<String> headers){
		this.headers = headers;
	}
	
	@Override
	public boolean hasMoreElements() {
		return headers.hasMoreElements();
	}

	@Override
	public String nextElement() {
		return StringEscapeUtils.escapeHtml4(headers.nextElement());
	}

}
