 package org.apache.shiro.spring.boot.antisamy.cache;


import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.shiro.spring.boot.antisamy.AntisamyProperties;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AntiSamy 对象缓存管理
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class AntiSamyCacheManager {
	
	private volatile static AntiSamyCacheManager singleton;
	protected static Logger LOG = LoggerFactory.getLogger(AntiSamyCacheManager.class);
	protected static ConcurrentMap<Policy, AntiSamy> COMPLIED_ANTISAMY = new ConcurrentHashMap<Policy, AntiSamy>();
	protected PolicyCacheManager policyCacheManager;
	
	public static AntiSamyCacheManager getInstance(PolicyCacheManager policyCacheManager) {
		if (singleton == null) {
			synchronized (AntiSamyCacheManager.class) {
				if (singleton == null) {
					singleton = new AntiSamyCacheManager(policyCacheManager);
				}
			}
		}
		return singleton;
	}
	
	private AntiSamyCacheManager(PolicyCacheManager policyCacheManager){
		this.policyCacheManager = policyCacheManager;
	}
	
	public AntiSamyWrapper getXssAntiSamyWrapper(String relativePath, int scanType, String[] policyHeaders) throws PolicyException{
		Policy xssPolicy = this.policyCacheManager.getXssPolicy(relativePath);
		return getXssAntiSamyWrapper(xssPolicy, scanType, policyHeaders);
	}
	
	public AntiSamyWrapper getXssAntiSamyWrapper(Policy xssPolicy, int scanType, String[] policyHeaders) throws PolicyException {
		if(xssPolicy == null) {
			throw new PolicyException("Policy Not Found.");
		}
		AntiSamy ret = COMPLIED_ANTISAMY.get(xssPolicy);
		if (ret != null) {
			return new AntiSamyWrapper(ret, xssPolicy, scanType, policyHeaders);
		}
		ret = new AntiSamy(xssPolicy);
		AntiSamy existing = COMPLIED_ANTISAMY.putIfAbsent(xssPolicy, ret);
		if (existing != null) {
			ret = existing;
		}
		return new AntiSamyWrapper(ret, xssPolicy, scanType, policyHeaders);
	}

	public AntiSamyWrapper getDefaultAntiSamyWrapper(int scanType, String[] policyHeaders) throws PolicyException {
		Policy xssPolicy = this.policyCacheManager.getXssPolicy(AntisamyProperties.DEFAULT_POLICY);
		return getXssAntiSamyWrapper(xssPolicy, scanType, policyHeaders);
	}
	
	public void destroy() {
		synchronized (COMPLIED_ANTISAMY) {
			policyCacheManager.destroy();
			COMPLIED_ANTISAMY.clear();
		}
	}
}

