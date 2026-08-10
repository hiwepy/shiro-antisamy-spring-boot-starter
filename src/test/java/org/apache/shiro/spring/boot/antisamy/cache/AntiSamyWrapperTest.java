package org.apache.shiro.spring.boot.antisamy.cache;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AntiSamyWrapper}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("AntiSamyWrapper Tests")
class AntiSamyWrapperTest {

    @Test
    @DisplayName("Constructor sets all fields")
    void testConstructor() {
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 0, null);
        assertThat(wrapper).isNotNull();
        assertThat(wrapper.getAntiSamy()).isNull();
        assertThat(wrapper.getPolicy()).isNull();
        assertThat(wrapper.getScanType()).isEqualTo(0);
        assertThat(wrapper.getPolicyHeaders()).isNull();
    }

    @Test
    @DisplayName("Getters and setters work correctly")
    void testGettersSetters() {
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 1, new String[]{"X-Test"});
        wrapper.setScanType(0);
        assertThat(wrapper.getScanType()).isEqualTo(0);
        wrapper.setPolicyHeaders(new String[]{"X-Custom"});
        assertThat(wrapper.getPolicyHeaders()).containsExactly("X-Custom");
        wrapper.setAntiSamy(null);
        assertThat(wrapper.getAntiSamy()).isNull();
        wrapper.setPolicy(null);
        assertThat(wrapper.getPolicy()).isNull();
    }
}
