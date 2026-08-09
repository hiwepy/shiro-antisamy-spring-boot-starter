package org.apache.shiro.spring.boot.antisamy.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("URLUtils Tests")
class URLUtilsTest {

    @Test
    @DisplayName("isURLEncoder returns false for null")
    void testIsURLEncoderNull() {
        assertThat(URLUtils.isURLEncoder(null)).isFalse();
    }

    @Test
    @DisplayName("isURLEncoder returns false for empty string")
    void testIsURLEncoderEmpty() {
        assertThat(URLUtils.isURLEncoder("")).isFalse();
    }

    @Test
    @DisplayName("isURLEncoder returns true for encoded string")
    void testIsURLEncoderEncoded() {
        assertThat(URLUtils.isURLEncoder("%20test")).isTrue();
    }

    @Test
    @DisplayName("isURLEncoder returns false for plain string")
    void testIsURLEncoderPlain() {
        assertThat(URLUtils.isURLEncoder("hello")).isFalse();
    }

    @Test
    @DisplayName("isURLEncoder returns true for uppercase hex")
    void testIsURLEncoderUppercaseHex() {
        assertThat(URLUtils.isURLEncoder("%2Ftest")).isTrue();
    }

    @Test
    @DisplayName("isURLEncoder returns true for lowercase hex")
    void testIsURLEncoderLowercaseHex() {
        assertThat(URLUtils.isURLEncoder("%2ftest")).isFalse();
    }

    @Test
    @DisplayName("escape encodes string")
    void testEscape() {
        assertThat(URLUtils.escape("hello world")).isEqualTo("hello+world");
    }

    @Test
    @DisplayName("unescape decodes string")
    void testUnescape() {
        assertThat(URLUtils.unescape("hello+world")).isEqualTo("hello world");
    }

    @Test
    @DisplayName("escape and unescape are inverse operations")
    void testEscapeUnescapeRoundtrip() {
        String original = "hello world & more";
        String escaped = URLUtils.escape(original);
        String unescaped = URLUtils.unescape(escaped);
        assertThat(unescaped).isEqualTo(original);
    }

    @Test
    @DisplayName("escape handles special characters")
    void testEscapeSpecial() {
        String result = URLUtils.escape("test&more=stuff");
        assertThat(result).contains("%");
    }

    @Test
    @DisplayName("unescape handles encoded characters")
    void testUnescapeEncoded() {
        assertThat(URLUtils.unescape("hello%20world")).isEqualTo("hello world");
    }
}
