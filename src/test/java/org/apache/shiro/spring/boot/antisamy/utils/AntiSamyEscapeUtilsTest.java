package org.apache.shiro.spring.boot.antisamy.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("AntiSamyEscapeUtils Tests")
class AntiSamyEscapeUtilsTest {

    @Test
    @DisplayName("escapeHtml returns null for null input")
    void testEscapeHtmlNull() {
        assertThat(AntiSamyEscapeUtils.escapeHtml(null)).isNull();
    }

    @Test
    @DisplayName("escapeHtml escapes HTML entities")
    void testEscapeHtmlEntities() {
        String result = AntiSamyEscapeUtils.escapeHtml("&");
        assertThat(result).isEqualTo("&amp;");
    }

    @Test
    @DisplayName("escapeHtml handles normal text")
    void testEscapeHtmlNormal() {
        String result = AntiSamyEscapeUtils.escapeHtml("hello");
        assertThat(result).isEqualTo("hello");
    }

    @Test
    @DisplayName("escapeHtml handles single quotes")
    void testEscapeHtmlSingleQuote() {
        String result = AntiSamyEscapeUtils.escapeHtml("it's");
        assertThat(result).contains("'");
    }

    @Test
    @DisplayName("escapeHtml handles double quotes")
    void testEscapeHtmlDoubleQuote() {
        String result = AntiSamyEscapeUtils.escapeHtml("\"test\"");
        assertThat(result).isNotNull();
        assertThat(result).contains("test");
    }

    @Test
    @DisplayName("escapeHtml handles backslash")
    void testEscapeHtmlBackslash() {
        String result = AntiSamyEscapeUtils.escapeHtml("test\\path");
        assertThat(result).contains("\\");
    }

    @Test
    @DisplayName("escapeHtml handles forward slash")
    void testEscapeHtmlForwardSlash() {
        String result = AntiSamyEscapeUtils.escapeHtml("test/path");
        assertThat(result).contains("/");
    }

    @Test
    @DisplayName("escapeHtml handles space")
    void testEscapeHtmlSpace() {
        String result = AntiSamyEscapeUtils.escapeHtml(" ");
        assertThat(result).isEqualTo("&nbsp;");
    }

    @Test
    @DisplayName("escapeHtml handles newline")
    void testEscapeHtmlNewline() {
        String result = AntiSamyEscapeUtils.escapeHtml("\n");
        assertThat(result).isEqualTo("\\n");
    }

    @Test
    @DisplayName("escapeHtml handles tab")
    void testEscapeHtmlTab() {
        String result = AntiSamyEscapeUtils.escapeHtml("\t");
        assertThat(result).isEqualTo("\\t");
    }

    @Test
    @DisplayName("escapeHtml handles carriage return")
    void testEscapeHtmlCr() {
        String result = AntiSamyEscapeUtils.escapeHtml("\r");
        assertThat(result).isEqualTo("\\r");
    }

    @Test
    @DisplayName("escapeHtml handles form feed")
    void testEscapeHtmlFormFeed() {
        String result = AntiSamyEscapeUtils.escapeHtml("\f");
        assertThat(result).isEqualTo("\\f");
    }

    @Test
    @DisplayName("escapeHtml handles backspace")
    void testEscapeHtmlBackspace() {
        String result = AntiSamyEscapeUtils.escapeHtml("\b");
        assertThat(result).isEqualTo("\\b");
    }

    @Test
    @DisplayName("escapeHtml handles control char < 32")
    void testEscapeHtmlControlChar() {
        String result = AntiSamyEscapeUtils.escapeHtml(String.valueOf((char) 1));
        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("escapeHtml handles less-than")
    void testEscapeHtmlLessThan() {
        String result = AntiSamyEscapeUtils.escapeHtml("<");
        assertThat(result).isEqualTo("&lt;");
    }

    @Test
    @DisplayName("escapeHtml handles greater-than")
    void testEscapeHtmlGreaterThan() {
        String result = AntiSamyEscapeUtils.escapeHtml(">");
        assertThat(result).isEqualTo("&gt;");
    }

    @Test
    @DisplayName("escapeHtml handles mixed content")
    void testEscapeHtmlMixed() {
        String result = AntiSamyEscapeUtils.escapeHtml("<b>bold</b>");
        assertThat(result).contains("&lt;");
        assertThat(result).contains("&gt;");
    }

    @Test
    @DisplayName("escapeHtml to Writer works")
    void testEscapeHtmlWriter() throws IOException {
        StringWriter writer = new StringWriter();
        AntiSamyEscapeUtils.escapeHtml(writer, "hello");
        assertThat(writer.toString()).isEqualTo("hello");
    }

    @Test
    @DisplayName("unescapeHtml returns null for null input")
    void testUnescapeHtmlNull() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml(null)).isNull();
    }

    @Test
    @DisplayName("unescapeHtml handles normal text")
    void testUnescapeHtmlNormal() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("hello")).isEqualTo("hello");
    }

    @Test
    @DisplayName("unescapeHtml handles escaped newline")
    void testUnescapeHtmlNewline() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("\\n")).isEqualTo("\n");
    }

    @Test
    @DisplayName("unescapeHtml handles escaped tab")
    void testUnescapeHtmlTab() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("\\t")).isEqualTo("\t");
    }

    @Test
    @DisplayName("unescapeHtml handles escaped carriage return")
    void testUnescapeHtmlCr() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("\\r")).isEqualTo("\r");
    }

    @Test
    @DisplayName("unescapeHtml handles escaped form feed")
    void testUnescapeHtmlFormFeed() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("\\f")).isEqualTo("\f");
    }

    @Test
    @DisplayName("unescapeHtml handles escaped backspace")
    void testUnescapeHtmlBackspace() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("\\b")).isEqualTo("\b");
    }

    @Test
    @DisplayName("unescapeHtml handles escaped backslash")
    void testUnescapeHtmlBackslash() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("\\\\")).isEqualTo("\\");
    }

    @Test
    @DisplayName("unescapeHtml handles escaped single quote")
    void testUnescapeHtmlSingleQuote() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("\\'")).isEqualTo("'");
    }

    @Test
    @DisplayName("unescapeHtml handles escaped double quote")
    void testUnescapeHtmlDoubleQuote() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("\\\"")).isEqualTo("\"");
    }

    @Test
    @DisplayName("unescapeHtml handles trailing backslash")
    void testUnescapeHtmlTrailingSlash() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("test\\")).isEqualTo("test\\");
    }

    @Test
    @DisplayName("unescapeHtml handles entity references")
    void testUnescapeHtmlEntity() {
        String result = AntiSamyEscapeUtils.unescapeHtml("&amp;");
        assertThat(result).isEqualTo("&");
    }

    @Test
    @DisplayName("unescapeHtml handles unknown entity")
    void testUnescapeHtmlUnknownEntity() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("&unknown;")).isEqualTo("&unknown;");
    }

    @Test
    @DisplayName("unescapeHtml handles incomplete entity")
    void testUnescapeHtmlIncompleteEntity() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("&test")).isEqualTo("&test");
    }

    @Test
    @DisplayName("unescapeHtml handles entity followed by ampersand")
    void testUnescapeHtmlEntityAmpersand() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("&amp&test;")).isNotNull();
    }

    @Test
    @DisplayName("unescapeHtml handles escaped default char")
    void testUnescapeHtmlEscapedDefault() {
        assertThat(AntiSamyEscapeUtils.unescapeHtml("\\x")).isEqualTo("x");
    }

    @Test
    @DisplayName("unescapeHtml to Writer works")
    void testUnescapeHtmlWriter() throws IOException {
        StringWriter writer = new StringWriter();
        AntiSamyEscapeUtils.unescapeHtml(writer, "hello");
        assertThat(writer.toString()).isEqualTo("hello");
    }

    @Test
    @DisplayName("escapeHtml throws on null Writer")
    void testEscapeHtmlNullWriter() {
        assertThatThrownBy(() -> AntiSamyEscapeUtils.escapeHtml(null, "test"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("unescapeHtml throws on null Writer")
    void testUnescapeHtmlNullWriter() {
        assertThatThrownBy(() -> AntiSamyEscapeUtils.unescapeHtml(null, "test"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("unescapeHtml handles null str with Writer")
    void testUnescapeHtmlNullStrWriter() throws IOException {
        StringWriter writer = new StringWriter();
        AntiSamyEscapeUtils.unescapeHtml(writer, null);
        assertThat(writer.toString()).isEmpty();
    }
}
