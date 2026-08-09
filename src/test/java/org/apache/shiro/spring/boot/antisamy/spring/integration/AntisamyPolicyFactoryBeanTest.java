package org.apache.shiro.spring.boot.antisamy.spring.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.validator.html.Policy;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AntisamyPolicyFactoryBean Tests")
class AntisamyPolicyFactoryBeanTest {

    @Test
    @DisplayName("getObjectType returns Policy.class")
    void testGetObjectType() {
        AntisamyPolicyFactoryBean factory = new AntisamyPolicyFactoryBean();
        assertThat(factory.getObjectType()).isEqualTo(Policy.class);
    }

    @Test
    @DisplayName("isSingleton returns true")
    void testIsSingleton() {
        AntisamyPolicyFactoryBean factory = new AntisamyPolicyFactoryBean();
        assertThat(factory.isSingleton()).isTrue();
    }

    @Test
    @DisplayName("policyConfigFilePath getter and setter work")
    void testPolicyConfigFilePath() {
        AntisamyPolicyFactoryBean factory = new AntisamyPolicyFactoryBean();
        factory.setPolicyConfigFilePath("classpath:test.xml");
        assertThat(factory.getPolicyConfigFilePath()).isEqualTo("classpath:test.xml");
    }
}
