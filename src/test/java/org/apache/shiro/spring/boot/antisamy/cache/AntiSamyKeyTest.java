package org.apache.shiro.spring.boot.antisamy.cache;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AntiSamyKey Tests")
class AntiSamyKeyTest {

    @Test
    @DisplayName("Constants have expected values")
    void testConstants() {
        assertThat(AntiSamyKey.MODULE_SPLIT_KEY).isEqualTo("moduleSplit");
        assertThat(AntiSamyKey.SCANTYPE_KEY).isEqualTo("scanType");
        assertThat(AntiSamyKey.INCLUDE_PATTERNS_KEY).isEqualTo("includePatterns");
        assertThat(AntiSamyKey.EXCLUDE_PATTERNS_KEY).isEqualTo("excludePatterns");
        assertThat(AntiSamyKey.DEFAULT_POLICY_KEY).isEqualTo("defaultPolicy");
        assertThat(AntiSamyKey.POLICY_MAPPINGS_KEY).isEqualTo("policyMappings");
        assertThat(AntiSamyKey.CONFIG_LOCATION_KEY).isEqualTo("configLocation");
    }
}
