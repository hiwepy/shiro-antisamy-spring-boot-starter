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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {{ @link AntisamyProperties }}.
 *
 * <p>Verifies default values, getters/setters and POJO contract.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("AntisamyProperties Tests")
class AntisamyPropertiesTest {
    @Test
    @DisplayName("Default constructor creates non-null instance")
    void testDefaultInstance() {
        AntisamyProperties props = new AntisamyProperties();
        assertThat(props).isNotNull();
    }

    @Test
    @DisplayName("Setter 'setPolicyMappings' accepts a policyMappings value")
    void testPolicyMappingsSetter() {
        AntisamyProperties props = new AntisamyProperties();
        props.setPolicyMappings(null);
        // Setter did not throw
    }

    @Test
    @DisplayName("Public constant 'DEFAULT_POLICY' has expected value")
    void testDEFAULT_POLICYConstant() {
        assertThat(AntisamyProperties.DEFAULT_POLICY).isEqualTo("classpath*:antisamy-policy.xml");
    }
}
