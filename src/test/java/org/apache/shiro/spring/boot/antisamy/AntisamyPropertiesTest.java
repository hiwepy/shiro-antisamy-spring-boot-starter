package org.apache.shiro.spring.boot.antisamy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AntisamyProperties Tests")
class AntisamyPropertiesTest {

    @Test
    @DisplayName("Default constructor creates non-null instance")
    void testDefaultInstance() {
        AntisamyProperties props = new AntisamyProperties();
        assertThat(props).isNotNull();
    }

    @Test
    @DisplayName("Default scanType is 1")
    void testDefaultScanType() {
        AntisamyProperties props = new AntisamyProperties();
        assertThat(props.getScanType()).isEqualTo(1);
    }

    @Test
    @DisplayName("scanType getter and setter")
    void testScanType() {
        AntisamyProperties props = new AntisamyProperties();
        props.setScanType(0);
        assertThat(props.getScanType()).isEqualTo(0);
    }

    @Test
    @DisplayName("includePatterns getter and setter")
    void testIncludePatterns() {
        AntisamyProperties props = new AntisamyProperties();
        props.setIncludePatterns(new String[]{"/api/**"});
        assertThat(props.getIncludePatterns()).containsExactly("/api/**");
    }

    @Test
    @DisplayName("excludePatterns getter and setter")
    void testExcludePatterns() {
        AntisamyProperties props = new AntisamyProperties();
        props.setExcludePatterns(new String[]{"/static/**"});
        assertThat(props.getExcludePatterns()).containsExactly("/static/**");
    }

    @Test
    @DisplayName("policyMappings getter and setter")
    void testPolicyMappings() {
        AntisamyProperties props = new AntisamyProperties();
        Map<String, String> mappings = new HashMap<>();
        mappings.put("/api/**", "classpath:policy.xml");
        props.setPolicyMappings(mappings);
        assertThat(props.getPolicyMappings()).containsEntry("/api/**", "classpath:policy.xml");
    }

    @Test
    @DisplayName("policyHeaders getter and setter")
    void testPolicyHeaders() {
        AntisamyProperties props = new AntisamyProperties();
        props.setPolicyHeaders(new String[]{"X-Test"});
        assertThat(props.getPolicyHeaders()).containsExactly("X-Test");
    }

    @Test
    @DisplayName("defaultPolicy getter and setter")
    void testDefaultPolicy() {
        AntisamyProperties props = new AntisamyProperties();
        props.setDefaultPolicy("classpath:custom.xml");
        assertThat(props.getDefaultPolicy()).isEqualTo("classpath:custom.xml");
    }

    @Test
    @DisplayName("DEFAULT_POLICY has expected value")
    void testDEFAULT_POLICYConstant() {
        assertThat(AntisamyProperties.DEFAULT_POLICY).isEqualTo("classpath*:antisamy-policy.xml");
    }

    @Test
    @DisplayName("Default includePatterns is null")
    void testDefaultIncludePatterns() {
        AntisamyProperties props = new AntisamyProperties();
        assertThat(props.getIncludePatterns()).isNull();
    }

    @Test
    @DisplayName("Default excludePatterns is null")
    void testDefaultExcludePatterns() {
        AntisamyProperties props = new AntisamyProperties();
        assertThat(props.getExcludePatterns()).isNull();
    }

    @Test
    @DisplayName("Default policyHeaders is null")
    void testDefaultPolicyHeaders() {
        AntisamyProperties props = new AntisamyProperties();
        assertThat(props.getPolicyHeaders()).isNull();
    }

    @Test
    @DisplayName("Default policyMappings is empty map")
    void testDefaultPolicyMappings() {
        AntisamyProperties props = new AntisamyProperties();
        assertThat(props.getPolicyMappings()).isNotNull();
        assertThat(props.getPolicyMappings()).isEmpty();
    }
}
