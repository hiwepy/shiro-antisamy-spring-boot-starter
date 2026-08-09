 package org.apache.shiro.spring.boot.antisamy.cache;


 import org.apache.shiro.spring.boot.antisamy.AntisamyProperties;
 import org.owasp.validator.html.AntiSamy;
 import org.owasp.validator.html.Policy;
 import org.owasp.validator.html.PolicyException;

 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.ConcurrentMap;

/**
 * AntiSamy objectmanagement
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class AntiSamyCacheManager {
	
	private volatile static AntiSamyCacheManager singleton;
	protected static ConcurrentMap<Policy, AntiSamy> COMPLIED_ANTISAMY = new ConcurrentHashMap<Policy, AntiSamy>();
	protected PolicyCacheManager policyCacheManager;
	
	/** Returns the instance.
	 * @param policyCacheManager the policyCacheManager
	 * @return the result
	 */
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
	
	/** Returns the xss anti samy wrapper.
	 * @param relativePath the relativePath
	 * @param scanType the scanType
	 * @param policyHeaders the policyHeaders
	 * @return the result
	 */
	public AntiSamyWrapper getXssAntiSamyWrapper(String relativePath, int scanType, String[] policyHeaders) throws PolicyException{
		Policy xssPolicy = this.policyCacheManager.getXssPolicy(relativePath);
		return getXssAntiSamyWrapper(xssPolicy, scanType, policyHeaders);
	}
	
	/** Returns the xss anti samy wrapper.
	 * @param xssPolicy the xssPolicy
	 * @param scanType the scanType
	 * @param policyHeaders the policyHeaders
	 * @return the result
	 */
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

	/** Returns the default anti samy wrapper.
	 * @param scanType the scanType
	 * @param policyHeaders the policyHeaders
	 * @return the result
	 */
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

