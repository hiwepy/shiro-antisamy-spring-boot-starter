package org.apache.shiro.spring.boot.antisamy.web.servlet.http;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Vector;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AntiSamyEnumeration Tests")
class AntiSamyEnumerationTest {

    @Test
    @DisplayName("hasMoreElements delegates to wrapped enumeration")
    void testHasMoreElements() {
        Vector<String> v = new Vector<>(Arrays.asList("a", "b"));
        Enumeration<String> wrapped = v.elements();
        AntiSamyEnumeration enum1 = new AntiSamyEnumeration(wrapped, null);
        assertThat(enum1.hasMoreElements()).isTrue();
    }

    @Test
    @DisplayName("hasMoreElements returns false when empty")
    void testHasMoreElementsEmpty() {
        Enumeration<String> wrapped = Collections.emptyEnumeration();
        AntiSamyEnumeration enum1 = new AntiSamyEnumeration(wrapped, null);
        assertThat(enum1.hasMoreElements()).isFalse();
    }

    @Test
    @DisplayName("nextElement delegates to wrapped enumeration")
    void testNextElement() {
        Vector<String> v = new Vector<>(Arrays.asList("test"));
        Enumeration<String> wrapped = v.elements();
        AntiSamyEnumeration enum1 = new AntiSamyEnumeration(wrapped, null);
        assertThat(enum1.nextElement()).isEqualTo("test");
    }
}
