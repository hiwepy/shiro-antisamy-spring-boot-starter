package org.apache.shiro.spring.boot.antisamy.cache;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PolicyCacheManager}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("PolicyCacheManager Tests")
class PolicyCacheManagerTest {

    @Test
    @DisplayName("getInstance returns singleton")
    void testGetInstance() {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        PolicyCacheManager instance = PolicyCacheManager.getInstance(resolver);
        assertThat(instance).isNotNull();
        PolicyCacheManager instance2 = PolicyCacheManager.getInstance(resolver);
        assertThat(instance).isSameAs(instance2);
    }

    @Test
    @DisplayName("getXssPolicy returns null for blank path")
    void testGetXssPolicyBlankPath() throws Exception {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        PolicyCacheManager manager = PolicyCacheManager.getInstance(resolver);
        assertThat(manager.getXssPolicy("")).isNull();
        assertThat(manager.getXssPolicy((String) null)).isNull();
    }

    @Test
    @DisplayName("getXssPolicy returns null for unreadable resource")
    void testGetXssPolicyUnreadable() throws Exception {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        Resource resource = mock(Resource.class);
        when(resolver.getResource(anyString())).thenReturn(resource);
        when(resource.isReadable()).thenReturn(false);
        PolicyCacheManager manager = PolicyCacheManager.getInstance(resolver);
        assertThat(manager.getXssPolicy("classpath:test.xml")).isNull();
    }

    @Test
    @DisplayName("getXssPolicy returns null for null resource")
    void testGetXssPolicyNullResource() throws Exception {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        when(resolver.getResource(anyString())).thenReturn(null);
        PolicyCacheManager manager = PolicyCacheManager.getInstance(resolver);
        assertThat(manager.getXssPolicy("classpath:test.xml")).isNull();
    }

    @Test
    @DisplayName("getXssPolicy(URL) returns null for null url")
    void testGetXssPolicyNullUrl() throws Exception {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        PolicyCacheManager manager = PolicyCacheManager.getInstance(resolver);
        assertThat(manager.getXssPolicy((java.net.URL) null)).isNull();
    }

    @Test
    @DisplayName("getXssPolicy(File) returns null for null file")
    void testGetXssPolicyNullFile() throws Exception {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        PolicyCacheManager manager = PolicyCacheManager.getInstance(resolver);
        assertThat(manager.getXssPolicy((java.io.File) null)).isNull();
    }

    @Test
    @DisplayName("getXssPolicy(File) returns null for non-existent file")
    void testGetXssPolicyNonExistentFile() throws Exception {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        PolicyCacheManager manager = PolicyCacheManager.getInstance(resolver);
        assertThat(manager.getXssPolicy(new java.io.File("/nonexistent.xml"))).isNull();
    }

    @Test
    @DisplayName("destroy clears the policy cache")
    void testDestroy() {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        PolicyCacheManager manager = PolicyCacheManager.getInstance(resolver);
        manager.destroy();
        assertThat(PolicyCacheManager.COMPLIED_POLICY).isEmpty();
    }
}
