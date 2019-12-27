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
package org.apache.shiro.spring.boot.antisamy.spring.integration;

import org.owasp.validator.html.Policy;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.util.ResourceUtils;

public class AntisamyPolicyFactoryBean implements FactoryBean<Policy>{

	/**
	 * policy配置文件路径
	 */
	private String policyConfigFilePath;
	
	@Override
	public Policy getObject() throws Exception {
		return Policy.getInstance(ResourceUtils.getFile(policyConfigFilePath));
	}

	@Override
	public Class<?> getObjectType() {
		return Policy.class;
	}

	@Override
	public boolean isSingleton() {
		return true;
	}

	public String getPolicyConfigFilePath() {
		return policyConfigFilePath;
	}

	public void setPolicyConfigFilePath(String policyConfigFilePath) {
		this.policyConfigFilePath = policyConfigFilePath;
	}

	
}
