package org.apache.shiro.spring.boot.antisamy.cache;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.support.ResourcePatternResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link AntiSamyCacheManager}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("AntiSamyCacheManager Tests")
class AntiSamyCacheManagerTest {

    @Test
    @DisplayName("getInstance returns singleton")
    void testGetInstance() {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        PolicyCacheManager policyCacheManager = PolicyCacheManager.getInstance(resolver);
        AntiSamyCacheManager instance = AntiSamyCacheManager.getInstance(policyCacheManager);
        assertThat(instance).isNotNull();
        AntiSamyCacheManager instance2 = AntiSamyCacheManager.getInstance(policyCacheManager);
        assertThat(instance).isSameAs(instance2);
    }

    @Test
    @DisplayName("destroy clears the antisamy cache")
    void testDestroy() {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        PolicyCacheManager policyCacheManager = PolicyCacheManager.getInstance(resolver);
        AntiSamyCacheManager manager = AntiSamyCacheManager.getInstance(policyCacheManager);
        manager.destroy();
        assertThat(AntiSamyCacheManager.COMPLIED_ANTISAMY).isEmpty();
    }
}
