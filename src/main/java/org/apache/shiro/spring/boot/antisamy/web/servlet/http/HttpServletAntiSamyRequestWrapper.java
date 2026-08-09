package org.apache.shiro.spring.boot.antisamy.web.servlet.http;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.apache.shiro.spring.boot.antisamy.cache.AntiSamyWrapper;
import org.apache.shiro.spring.boot.antisamy.utils.AntiSamyScanUtils;
import org.apache.shiro.spring.boot.antisamy.utils.XssScanUtils;

/**
 * RichText XSS(Cross Site Scripting)，request
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class HttpServletAntiSamyRequestWrapper extends HttpServletRequestWrapper {

	private AntiSamyWrapper antiSamyWrapper = null;
	
	public HttpServletAntiSamyRequestWrapper(AntiSamyWrapper antiSamyWrapper,HttpServletRequest request) {
		super(request);
		this.antiSamyWrapper = antiSamyWrapper;
	}
	
	@Override
	/** Returns the parameter map.
	 * @return the result
	 */
	public Map<String, String[]> getParameterMap() {
		Map<String, String[]> request_map = super.getParameterMap();
		Iterator<Entry<String, String[]>> iterator = request_map.entrySet().iterator();
		while (iterator.hasNext()) {
			Entry<String, String[]> me = iterator.next();
			String[] values = (String[]) me.getValue();
			for (int i = 0; i < values.length; i++) {
				// /System.out.println(values[i]);
				values[i] = xssClean(values[i]);
			}
		}
		return request_map;
	}

	@Override
	/** Returns the parameter values.
	 * @param name the name
	 * @return the result
	 */
	public String[] getParameterValues(String name) {
		String[] rawValues = super.getParameterValues(name);
		if (rawValues == null){
			return null;
		}
		String[] cleanedValues = new String[rawValues.length];
		for (int i = 0; i < rawValues.length; i++) {
			cleanedValues[i] = xssClean(rawValues[i]);
		}
		return cleanedValues;
	}

	@Override
	/** Returns the parameter.
	 * @param name the name
	 * @return the result
	 */
	public String getParameter(String name) {
		String str = super.getParameter(name);
		if (str == null){
			return null;
		}
		return xssClean(str);
	}

	@Override
	/** Returns the headers.
	 * @param name the name
	 * @return the result
	 */
	public Enumeration<String> getHeaders(String name) {
		if(XssScanUtils.isXssHeader(antiSamyWrapper.getPolicyHeaders(), name)){
			return new AntiSamyEnumeration( super.getHeaders(name), antiSamyWrapper);
		}
        return super.getHeaders(name);
    }
	
	@Override
	/** Returns the header.
	 * @param name the name
	 * @return the result
	 */
	public String getHeader(String name) {
		String value = super.getHeader(name);
		if (value == null){
			return null;
		}
		if(XssScanUtils.isXssHeader(antiSamyWrapper.getPolicyHeaders(), name)){
			return xssClean(value);
		}
		return value;
	}
	
	@Override
	/** Returns the cookies.
	 * @return the result
	 */
	public Cookie[] getCookies() {
		Cookie[] existingCookies = super.getCookies();
		if (existingCookies != null) {
			for (int i = 0; i < existingCookies.length; ++i) {
				Cookie cookie = existingCookies[i];
				cookie.setValue(xssClean(cookie.getValue()));
			}
		}
		return existingCookies;
	}

	@Override
	/** Returns the query string.
	 * @return the result
	 */
	public String getQueryString() {
		return xssClean(super.getQueryString());
	}

	public String xssClean(String taintedHTML) {
		return AntiSamyScanUtils.xssClean(_getHttpServletRequest(), antiSamyWrapper, taintedHTML);
	}
	
	protected HttpServletRequest _getHttpServletRequest() {
		 return (HttpServletRequest) super.getRequest();
    }

}
