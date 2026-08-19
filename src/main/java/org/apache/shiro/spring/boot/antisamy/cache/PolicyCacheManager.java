package org.apache.shiro.spring.boot.antisamy.cache;

import java.io.File;
import java.net.URL;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.util.StringUtils;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;

/**
 * Policyobjectmanagement
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class PolicyCacheManager {
	
	private volatile static PolicyCacheManager singleton;
	protected static Logger LOG = LoggerFactory.getLogger(PolicyCacheManager.class);
	protected static ConcurrentMap<String, Policy> COMPLIED_POLICY = new ConcurrentHashMap<String, Policy>();
	/**
	 * get Instance.
	 *
	 * @param resourceResolver the resource resolver
	 * @return the result
	 */
	protected ResourcePatternResolver resourceResolver;
	
	/** Returns the instance.
	 * @param resourceResolver the resourceResolver
	 * @return the result
	 */
	public static PolicyCacheManager getInstance(ResourcePatternResolver resourceResolver) {
		if (singleton == null) {
			synchronized (PolicyCacheManager.class) {
				if (singleton == null) {
					singleton = new PolicyCacheManager(resourceResolver);
				}
			}
		}
		return singleton;
	}
	
	private PolicyCacheManager(ResourcePatternResolver resourceResolver){
		this.resourceResolver = resourceResolver;
	}
	
	/** Returns the xss policy.
	 * @param relativePath the relativePath
	 * @return the result
	 */
	public Policy getXssPolicy(String relativePath) throws PolicyException {
		try {
			
			if(!StringUtils.hasText(relativePath)){
				return null;
			}
			Resource resource = resourceResolver.getResource(relativePath);
			if(resource == null || !resource.isReadable()) {
				return null;
			}
			
			Policy ret = COMPLIED_POLICY.get(resource.getURL().getPath());
			if (ret != null) {
				return ret;
			}
			ret = Policy.getInstance(resource.getInputStream());
			Policy existing = COMPLIED_POLICY.putIfAbsent(resource.getURL().getPath(), ret);
			if (existing != null) {
				ret = existing;
			}
			return ret;
		} catch (Exception e) {
			throw new PolicyException(e);
		}
	}
	
	/** Returns the xss policy.
	 * @param url the url
	 * @return the result
	 */
	public Policy getXssPolicy(URL url) throws PolicyException{
		try {
			if(url == null){
				return null;
			}
			Policy ret = COMPLIED_POLICY.get(url.toString());
			if (ret != null) {
				return ret;
			}
			ret = Policy.getInstance(url);
			Policy existing = COMPLIED_POLICY.putIfAbsent(url.getPath(), ret);
			if (existing != null) {
				ret = existing;
			}
			return ret;
		} catch (Exception e) {
			if(e instanceof PolicyException) {
				throw e;
			}
			throw new PolicyException(e);
		}
	}
	
	/** Returns the xss policy.
	 * @param policy the policy
	 * @return the result
	 */
	public Policy getXssPolicy(File policy) throws PolicyException {
		try {
			if(policy == null || !policy.exists() || !policy.isFile()){
				return null;
			}
			Policy ret = COMPLIED_POLICY.get(policy.getName());
			if (ret != null) {
				return ret;
			}
			ret = Policy.getInstance(policy);
			Policy existing = COMPLIED_POLICY.putIfAbsent(policy.getName(), ret);
			if (existing != null) {
				ret = existing;
			}
			return ret;
		} catch (Exception e) {
			if(e instanceof PolicyException) {
				throw e;
			}
			throw new PolicyException(e);
		}
	}
	
	/**
	 * destroy.
	 *
	 */
	public void destroy() {
		synchronized (COMPLIED_POLICY) {
			COMPLIED_POLICY.clear();
		}
	}
	
}

