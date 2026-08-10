/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.antisamy;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.shiro.spring.boot.antisamy.config.Ini;
import org.apache.shiro.util.CollectionUtils;

/**
 * TODO
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class AntisamyProperties {

	public static final String DEFAULT_POLICY = "classpath*:antisamy-policy.xml";
	
	/** 扫描器类型，0：DOM类型扫描器,1:SAX类型扫描器；两者的区别如同XML解析中DOM解析与Sax解析区别相同，实际上就是对两种解析方式的实现*/
	protected int scanType = 1;
	/** 请求路径的正则匹配表达式，匹配的路径会被检测XSS*/
	protected String[] includePatterns = null;
	/** 不进行过滤请求路径的正则匹配表达式，匹配的路径不会被检测XSS*/
	protected String[] excludePatterns = null;
	/**防XSS攻击的模块对应的规则配置*/
	protected Map<String,String> policyMappings = new HashMap<String,String>();
	/**需要进行Xss检查的Header*/
	protected String[] policyHeaders = null;
	/**默认的防XSS攻击的规则配置*/
	protected String defaultPolicy = DEFAULT_POLICY;

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

	/** Returns the include patterns.
	 * @return the result
	 */
	public String[] getIncludePatterns() {
		return includePatterns;
	}

	/** Sets the include patterns.
	 * @param includePatterns the includePatterns
	 */
	public void setIncludePatterns(String[] includePatterns) {
		this.includePatterns = includePatterns;
	}

	/** Returns the exclude patterns.
	 * @return the result
	 */
	public String[] getExcludePatterns() {
		return excludePatterns;
	}

	/** Sets the exclude patterns.
	 * @param excludePatterns the excludePatterns
	 */
	public void setExcludePatterns(String[] excludePatterns) {
		this.excludePatterns = excludePatterns;
	}

	/** Returns the policy mappings.
	 * @return the result
	 */
	public Map<String, String> getPolicyMappings() {
		return policyMappings;
	}

	/** Sets the policy mappings.
	 * @param policyMappings the policyMappings
	 */
	public void setPolicyMappings(Map<String, String> policyMappings) {
		this.policyMappings = policyMappings;
	}

	/** Sets the policy definitions.
	 * @param policyDefinitions the policyDefinitions
	 */
	public void setPolicyDefinitions(String policyDefinitions) {
		try {
			Ini ini = new Ini();
			ini.load(policyDefinitions);
			Ini.Section section = ini.getSection("urls");
			if (CollectionUtils.isEmpty(section)) {
			    section = ini.getSection(Ini.DEFAULT_SECTION_NAME);
			}
			setPolicyMappings(section);
		} catch (IOException e) {
			e.printStackTrace();
		}
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

	/** Returns the default policy.
	 * @return the result
	 */
	public String getDefaultPolicy() {
		return defaultPolicy;
	}

	/** Sets the default policy.
	 * @param defaultPolicy the defaultPolicy
	 */
	public void setDefaultPolicy(String defaultPolicy) {
		this.defaultPolicy = defaultPolicy;
	}
	
}
