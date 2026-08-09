package org.apache.shiro.spring.boot.antisamy.web.servlet.http;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.apache.shiro.spring.boot.antisamy.cache.AntiSamyWrapper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("HttpServletAntiSamyRequestWrapper Tests")
class HttpServletAntiSamyRequestWrapperTest {

    private HttpServletRequest createMockRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameterMap()).thenReturn(new HashMap<>());
        when(request.getParameterValues("key")).thenReturn(new String[]{"value"});
        when(request.getParameter("key")).thenReturn("value");
        when(request.getHeaders("X-Test")).thenReturn(Collections.enumeration(Collections.singletonList("headerValue")));
        when(request.getHeader("X-Test")).thenReturn("headerValue");
        when(request.getCookies()).thenReturn(null);
        when(request.getQueryString()).thenReturn("q=test");
        when(request.getRequestURI()).thenReturn("/test");
        return request;
    }

    @Test
    @DisplayName("Constructor creates non-null wrapper")
    void testConstructor() {
        HttpServletRequest request = createMockRequest();
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 0, null);
        HttpServletAntiSamyRequestWrapper wrapperReq = new HttpServletAntiSamyRequestWrapper(wrapper, request);
        assertThat(wrapperReq).isNotNull();
    }

    @Test
    @DisplayName("getParameterMap returns map")
    void testGetParameterMap() {
        HttpServletRequest request = createMockRequest();
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 0, null);
        HttpServletAntiSamyRequestWrapper wrapperReq = new HttpServletAntiSamyRequestWrapper(wrapper, request);
        Map<String, String[]> map = wrapperReq.getParameterMap();
        assertThat(map).isNotNull();
    }

    @Test
    @DisplayName("getParameterValues returns null for missing key")
    void testGetParameterValuesNull() {
        HttpServletRequest request = createMockRequest();
        when(request.getParameterValues("missing")).thenReturn(null);
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 0, null);
        HttpServletAntiSamyRequestWrapper wrapperReq = new HttpServletAntiSamyRequestWrapper(wrapper, request);
        assertThat(wrapperReq.getParameterValues("missing")).isNull();
    }

    @Test
    @DisplayName("getParameter returns null for missing key")
    void testGetParameterNull() {
        HttpServletRequest request = createMockRequest();
        when(request.getParameter("missing")).thenReturn(null);
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 0, null);
        HttpServletAntiSamyRequestWrapper wrapperReq = new HttpServletAntiSamyRequestWrapper(wrapper, request);
        assertThat(wrapperReq.getParameter("missing")).isNull();
    }

    @Test
    @DisplayName("getHeaders returns enumeration")
    void testGetHeaders() {
        HttpServletRequest request = createMockRequest();
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 0, new String[]{"X-Test"});
        HttpServletAntiSamyRequestWrapper wrapperReq = new HttpServletAntiSamyRequestWrapper(wrapper, request);
        Enumeration<String> headers = wrapperReq.getHeaders("X-Test");
        assertThat(headers).isNotNull();
    }

    @Test
    @DisplayName("getHeader returns null for missing header")
    void testGetHeaderNull() {
        HttpServletRequest request = createMockRequest();
        when(request.getHeader("X-Missing")).thenReturn(null);
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 0, null);
        HttpServletAntiSamyRequestWrapper wrapperReq = new HttpServletAntiSamyRequestWrapper(wrapper, request);
        assertThat(wrapperReq.getHeader("X-Missing")).isNull();
    }

    @Test
    @DisplayName("getHeader returns value for non-policy header")
    void testGetHeaderNonPolicy() {
        HttpServletRequest request = createMockRequest();
        when(request.getHeader("X-Other")).thenReturn("otherValue");
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 0, new String[]{"X-Test"});
        HttpServletAntiSamyRequestWrapper wrapperReq = new HttpServletAntiSamyRequestWrapper(wrapper, request);
        assertThat(wrapperReq.getHeader("X-Other")).isEqualTo("otherValue");
    }

    @Test
    @DisplayName("getCookies returns null when no cookies")
    void testGetCookies() {
        HttpServletRequest request = createMockRequest();
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 0, null);
        HttpServletAntiSamyRequestWrapper wrapperReq = new HttpServletAntiSamyRequestWrapper(wrapper, request);
        assertThat(wrapperReq.getCookies()).isNull();
    }
}
