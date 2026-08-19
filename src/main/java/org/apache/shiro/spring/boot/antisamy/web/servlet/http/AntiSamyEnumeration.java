package org.apache.shiro.spring.boot.antisamy.web.servlet.http;

import java.util.Enumeration;

import org.apache.shiro.spring.boot.antisamy.cache.AntiSamyWrapper;
import org.apache.shiro.spring.boot.antisamy.utils.AntiSamyScanUtils;
/** The Anti Samy Enumeration.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public class AntiSamyEnumeration implements Enumeration<String> {
	
	/**AntiSamyProxy对象*/
	private AntiSamyWrapper antiSamyProxy = null;
	/**原始Header*/
	private Enumeration<String> headers;
	
	/**
	 * Constructs a new anti samy enumeration instance.
	 *
	 * @param headers the headers
	 * @param antiSamyProxy the anti samy proxy
	 */
	public AntiSamyEnumeration(Enumeration<String> headers, AntiSamyWrapper antiSamyProxy){
		this.antiSamyProxy = antiSamyProxy;
		this.headers = headers;
	}
	
	/**
	 * Determines whether has more elements.
	 *
	 * @return the result
	 */
	@Override
	public boolean hasMoreElements() {
		return headers.hasMoreElements();
	}

	/**
	 * next Element.
	 *
	 * @return the result
	 */
	@Override
	public String nextElement() {
		return AntiSamyScanUtils.xssClean( antiSamyProxy, headers.nextElement());
	}

}
