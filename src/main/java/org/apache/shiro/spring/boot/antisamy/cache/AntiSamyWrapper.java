package org.apache.shiro.spring.boot.antisamy.cache;

import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;
/** The Anti Samy Wrapper.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public class AntiSamyWrapper {

	/**AntiSamy对象*/
	protected AntiSamy antiSamy;
	/**Policy策略对象*/
	protected Policy policy;
	/** 扫描器类型，0：DOM类型扫描器,1:SAX类型扫描器；两者的区别如同XML解析中DOM解析与Sax解析区别相同，实际上就是对两种解析方式的实现*/
	protected int scanType = 1;
	/**需要进行Xss检查的Header*/
	protected String[] policyHeaders;
	
	public AntiSamyWrapper(AntiSamy antiSamy,Policy policy, int scanType, String[] policyHeaders) {
		this.antiSamy = antiSamy;
		this.policy = policy;
		this.scanType = scanType;
		this.policyHeaders = policyHeaders;
	}

	/** Returns the anti samy.
	 * @return the result
	 */
	public AntiSamy getAntiSamy() {
		return antiSamy;
	}

	/** Sets the anti samy.
	 * @param antiSamy the antiSamy
	 */
	public void setAntiSamy(AntiSamy antiSamy) {
		this.antiSamy = antiSamy;
	}

	/** Returns the policy.
	 * @return the result
	 */
	public Policy getPolicy() {
		return policy;
	}

	/** Sets the policy.
	 * @param policy the policy
	 */
	public void setPolicy(Policy policy) {
		this.policy = policy;
	}

	/** Returns the scan type.
	 * @return the result
	 */
	public int getScanType() {
		return scanType;
	}

	/** Sets the scan type.
	 * @param scanType the scanType
	 */
	public void setScanType(int scanType) {
		this.scanType = scanType;
	}

	/** Returns the policy headers.
	 * @return the result
	 */
	public String[] getPolicyHeaders() {
		return policyHeaders;
	}

	/** Sets the policy headers.
	 * @param policyHeaders the policyHeaders
	 */
	public void setPolicyHeaders(String[] policyHeaders) {
		this.policyHeaders = policyHeaders;
	}
	
}
