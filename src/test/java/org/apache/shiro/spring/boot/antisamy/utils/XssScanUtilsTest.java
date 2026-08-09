package org.apache.shiro.spring.boot.antisamy.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("XssScanUtils Tests")
class XssScanUtilsTest {

    @Test
    @DisplayName("isXssHeader returns false for null headers")
    void testNullHeaders() {
        assertThat(XssScanUtils.isXssHeader(null, "X-Test")).isFalse();
    }

    @Test
    @DisplayName("isXssHeader returns false for empty headers")
    void testEmptyHeaders() {
        assertThat(XssScanUtils.isXssHeader(new String[]{}, "X-Test")).isFalse();
    }

    @Test
    @DisplayName("isXssHeader returns true when header is present")
    void testHeaderPresent() {
        assertThat(XssScanUtils.isXssHeader(new String[]{"X-Test", "X-Custom"}, "X-Test")).isTrue();
    }

    @Test
    @DisplayName("isXssHeader returns false when header is not present")
    void testHeaderNotPresent() {
        assertThat(XssScanUtils.isXssHeader(new String[]{"X-Test"}, "X-Custom")).isFalse();
    }
}
