/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
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
package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.antisamy.AntisamyProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(ShiroAntisamyProperties.PREFIX)
public class ShiroAntisamyProperties extends AntisamyProperties {
	
	public static final String PREFIX = "shiro.antisamy";
	
	/** 是否启用 **/
	private boolean enabled = false;

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
}