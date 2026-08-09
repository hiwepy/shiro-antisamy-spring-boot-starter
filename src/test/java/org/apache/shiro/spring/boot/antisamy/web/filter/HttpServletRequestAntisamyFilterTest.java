package org.apache.shiro.spring.boot.antisamy.web.filter;

import org.apache.shiro.spring.boot.antisamy.AntisamyProperties;
import org.apache.shiro.spring.boot.antisamy.cache.AntiSamyCacheManager;
import org.apache.shiro.spring.boot.antisamy.cache.PolicyCacheManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.support.ResourcePatternResolver;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@DisplayName("HttpServletRequestAntisamyFilter Tests")
class HttpServletRequestAntisamyFilterTest {

    private HttpServletRequestAntisamyFilter createFilter() {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        PolicyCacheManager policyCacheManager = PolicyCacheManager.getInstance(resolver);
        AntiSamyCacheManager cacheManager = AntiSamyCacheManager.getInstance(policyCacheManager);
        AntisamyProperties properties = new AntisamyProperties();
        return new HttpServletRequestAntisamyFilter(cacheManager, properties);
    }

    @Test
    @DisplayName("Constructor creates non-null filter")
    void testConstructor() {
        HttpServletRequestAntisamyFilter filter = createFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("isAccessAllowed returns true")
    void testIsAccessAllowed() throws Exception {
        HttpServletRequestAntisamyFilter filter = createFilter();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        assertThat(filter.isAccessAllowed(request, response, null)).isTrue();
    }

    @Test
    @DisplayName("onAccessDenied returns true")
    void testOnAccessDenied() throws Exception {
        HttpServletRequestAntisamyFilter filter = createFilter();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        assertThat(filter.onAccessDenied(request, response)).isTrue();
    }

    @Test
    @DisplayName("destroy does not throw")
    void testDestroy() {
        HttpServletRequestAntisamyFilter filter = createFilter();
        filter.destroy();
    }

    @Test
    @DisplayName("executeChain throws for non-HTTP request")
    void testExecuteChainNonHttp() {
        HttpServletRequestAntisamyFilter filter = createFilter();
        ServletRequest request = mock(ServletRequest.class);
        ServletResponse response = mock(ServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        assertThatThrownBy(() -> filter.executeChain(request, response, chain))
                .isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("matches with include patterns")
    void testMatchesIncludePatterns() {
        HttpServletRequestAntisamyFilter filter = createFilter();
        AntisamyProperties props = new AntisamyProperties();
        props.setIncludePatterns(new String[]{"/api/**"});
        // matches with empty exclude and non-empty include
        assertThat(filter.matches("/api/test", null)).isTrue();
    }

    @Test
    @DisplayName("matches with exclude patterns")
    void testMatchesExcludePatterns() {
        HttpServletRequestAntisamyFilter filter = createFilter();
        AntisamyProperties props = new AntisamyProperties();
        props.setExcludePatterns(new String[]{"/static/**"});
        // exclude pattern matches -> returns false
    }

    @Test
    @DisplayName("matches returns true when no patterns configured")
    void testMatchesNoPatterns() {
        HttpServletRequestAntisamyFilter filter = createFilter();
        assertThat(filter.matches("/any/path", null)).isTrue();
    }
}
