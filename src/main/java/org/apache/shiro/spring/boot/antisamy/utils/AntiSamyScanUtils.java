package org.apache.shiro.spring.boot.antisamy.utils;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.shiro.spring.boot.antisamy.cache.AntiSamyWrapper;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * XSS扫描过滤工具
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class AntiSamyScanUtils {
	
	protected static Logger LOG = LoggerFactory.getLogger(AntiSamyScanUtils.class);
	protected static Pattern HTML_PATTERN = Pattern.compile("<[^>]+>");
	protected static ConcurrentMap<String, String> COMPLIED_FIXS = new ConcurrentHashMap<String, String>();
	
	protected static String fix(AntiSamyWrapper proxy, String tag, String esc) throws ScanException, PolicyException {
		// AntiSamy对象
		AntiSamy antiSamy = proxy.getAntiSamy();
		//Policy策略对象
		Policy policy = proxy.getPolicy();
		// 扫描器类型，0：DOM类型扫描器,1:SAX类型扫描器；两者的区别如同XML解析中DOM解析与Sax解析区别相同，实际上就是对两种解析方式的实现
		int scanType = proxy.getScanType();
		String ret = COMPLIED_FIXS.get(tag);
		if( ret != null){
			return ret;
		}
		ret =  ( policy != null ? antiSamy.scan(esc, policy, scanType) : antiSamy.scan(esc, scanType)).getCleanHTML();
		String existing = COMPLIED_FIXS.putIfAbsent(tag, ret);
		if (existing != null) {
			ret = existing;
		}
		return ret;
	}
	
	public static String xssClean(AntiSamyWrapper proxy, String taintedHTML, boolean cleanbad) {
		if (proxy != null && taintedHTML != null) {
			try {
				// 进行解码：防止攻击者，采用转码方式进行注入
        		taintedHTML = URLUtils.unescape(taintedHTML);
				// AntiSamy对象
				AntiSamy antiSamy = proxy.getAntiSamy();
				//Policy策略对象
				Policy policy = proxy.getPolicy();
				// 扫描器类型，0：DOM类型扫描器,1:SAX类型扫描器；两者的区别如同XML解析中DOM解析与Sax解析区别相同，实际上就是对两种解析方式的实现
				int scanType = proxy.getScanType();
				LOG.debug("Tainted HTML :" + taintedHTML);
				//XSS扫描
				CleanResults cr = policy != null ?  antiSamy.scan(taintedHTML, policy, scanType) : antiSamy.scan(taintedHTML, scanType) ;
				String cleanHTML = cr.getCleanHTML();
				LOG.debug("XSS CleanHTML :" + cleanHTML);
				//处理一些特殊异常Bug
				if( HTML_PATTERN.matcher(taintedHTML).find() && cleanbad ){
					//安全的HTML输出
					cleanHTML = StringEscapeUtils.unescapeHtml4(cleanHTML);
					LOG.debug("UNEscape Html4 :" + cleanHTML);
					//解决“&nbsp;”转换成乱码问题
					cleanHTML = cleanHTML.replace(fix(proxy, "nbsp", "&nbsp;"), "&nbsp;" );
					//解决“&ensp;”转换成乱码问题
					cleanHTML = cleanHTML.replace(fix(proxy, "ensp", "&ensp;"), "&ensp;" );
				    LOG.debug("Fixed CleanHTML :" + cleanHTML);
				}
			    return cleanHTML;
			} catch (ScanException e) {
				LOG.error("XSS Scan Exception:" + e.getLocalizedMessage());
			} catch (PolicyException e) {
				LOG.error(e.getLocalizedMessage());
			}
		}
		return taintedHTML;
	}
	
	public static String xssClean(HttpServletRequest request, AntiSamyWrapper proxy, String taintedHTML) {
		String cleanbadStr = request.getParameter("cleanbad");
		boolean cleanbad = Boolean.parseBoolean((cleanbadStr != null && cleanbadStr.trim().length() > 0) ? cleanbadStr.trim() : "true" ) ;
		return xssClean(proxy, taintedHTML, cleanbad);
	}
	
	public static String xssClean(AntiSamyWrapper proxy,String taintedHTML) {
		if (proxy != null && taintedHTML != null) {
			try {
				// AntiSamy对象
				AntiSamy antiSamy = proxy.getAntiSamy();
				//Policy策略对象
				Policy policy = proxy.getPolicy();
				// 扫描器类型，0：DOM类型扫描器,1:SAX类型扫描器；两者的区别如同XML解析中DOM解析与Sax解析区别相同，实际上就是对两种解析方式的实现
				int scanType = proxy.getScanType();
				LOG.debug("Tainted :" + taintedHTML);
				//XSS扫描
				CleanResults cr = policy != null ?  antiSamy.scan(taintedHTML, policy, scanType) : antiSamy.scan(taintedHTML, scanType) ;
				String cleanHTML = cr.getCleanHTML();
				LOG.debug("XSS Clean :" + cleanHTML);
			    return cleanHTML;
			} catch (ScanException e) {
				LOG.error("XSS Scan Exception:" + e.getLocalizedMessage());
			} catch (PolicyException e) {
				LOG.error(e.getLocalizedMessage());
			}
		}
		return taintedHTML;
	}

}
