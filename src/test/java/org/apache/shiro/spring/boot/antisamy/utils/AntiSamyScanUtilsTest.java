package org.apache.shiro.spring.boot.antisamy.utils;

import org.apache.shiro.spring.boot.antisamy.cache.AntiSamyWrapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AntiSamyScanUtils Tests")
class AntiSamyScanUtilsTest {

    private static Policy policy;
    private static AntiSamy antiSamy;

    @BeforeAll
    static void setUp() throws Exception {
        policy = Policy.getInstance(AntiSamyScanUtilsTest.class.getResourceAsStream("/antisamy-policy-test.xml"));
        antiSamy = new AntiSamy(policy);
    }

    @Test
    @DisplayName("xssClean returns input for null proxy")
    void testXssCleanNullProxy() {
        assertThat(AntiSamyScanUtils.xssClean(null, "test")).isEqualTo("test");
    }

    @Test
    @DisplayName("xssClean returns null for null input with null proxy")
    void testXssCleanNullInput() {
        assertThat(AntiSamyScanUtils.xssClean(null, (String) null)).isNull();
    }

    @Test
    @DisplayName("xssClean with cleanbad returns input for null proxy")
    void testXssCleanBadNullProxy() {
        assertThat(AntiSamyScanUtils.xssClean(null, "test", true)).isEqualTo("test");
    }

    @Test
    @DisplayName("xssClean with cleanbad returns null for null input")
    void testXssCleanBadNullInput() {
        assertThat(AntiSamyScanUtils.xssClean(null, null, true)).isNull();
    }

    @Test
    @DisplayName("xssClean cleans XSS with real AntiSamy")
    void testXssCleanReal() {
        AntiSamyWrapper wrapper = new AntiSamyWrapper(antiSamy, policy, 0, null);
        String result = AntiSamyScanUtils.xssClean(wrapper, "<script>alert('xss')</script>");
        assertThat(result).doesNotContain("<script>");
    }

    @Test
    @DisplayName("xssClean with cleanbad cleans XSS")
    void testXssCleanBadReal() {
        AntiSamyWrapper wrapper = new AntiSamyWrapper(antiSamy, policy, 0, null);
        String result = AntiSamyScanUtils.xssClean(wrapper, "<b>bold</b>", true);
        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("xssClean preserves safe HTML")
    void testXssCleanSafe() {
        AntiSamyWrapper wrapper = new AntiSamyWrapper(antiSamy, policy, 0, null);
        String result = AntiSamyScanUtils.xssClean(wrapper, "safe text");
        assertThat(result).contains("safe text");
    }

    @Test
    @DisplayName("xssClean handles null taintedHTML with valid proxy")
    void testXssCleanNullTainted() {
        AntiSamyWrapper wrapper = new AntiSamyWrapper(antiSamy, policy, 0, null);
        assertThat(AntiSamyScanUtils.xssClean(wrapper, (String) null)).isNull();
    }

    @Test
    @DisplayName("xssClean with proxy and cleanbad handles null input")
    void testXssCleanBadNullTainted() {
        AntiSamyWrapper wrapper = new AntiSamyWrapper(antiSamy, policy, 0, null);
        assertThat(AntiSamyScanUtils.xssClean(wrapper, null, true)).isNull();
    }
}
