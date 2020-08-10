package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.antisamy.cache.AntiSamyCacheManager;
import org.apache.shiro.spring.boot.antisamy.cache.PolicyCacheManager;
import org.apache.shiro.spring.boot.antisamy.web.filter.HttpServletRequestAntisamyFilter;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.support.ResourcePatternResolver;

/*
 * 默认拦截器
 * <p>Shiro内置了很多默认的拦截器，比如身份验证、授权等相关的。默认拦截器可以参考org.apache.shiro.web.filter.mgt.DefaultFilter中的枚举拦截器：&nbsp;&nbsp;</p>
 * 自定义Filter通过@Bean注解后，被Spring Boot自动注册到了容器的Filter chain中，这样导致的结果是，所有URL都会被自定义Filter过滤，而不是Shiro中配置的一部分URL。
 */
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration" // shiro-spring-boot-web-starter
})
@ConditionalOnWebApplication
@ConditionalOnClass({ org.owasp.validator.html.AntiSamy.class })
@ConditionalOnProperty(prefix = ShiroAntisamyProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties(ShiroAntisamyProperties.class)
public class ShiroAntisamyWebFilterConfiguration extends AbstractShiroWebFilterConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public PolicyCacheManager policyCacheManager(ResourcePatternResolver resourceResolver) {
		return PolicyCacheManager.getInstance(resourceResolver);
	}
	
	@Bean
	@ConditionalOnMissingBean
	public AntiSamyCacheManager antiSamyCacheManager(PolicyCacheManager policyCacheManager) {
		return AntiSamyCacheManager.getInstance(policyCacheManager);
	}
	
	@Bean("antisamy")
	@ConditionalOnMissingBean(name = "antisamy")
	public FilterRegistrationBean<HttpServletRequestAntisamyFilter> antisamyFilter(AntiSamyCacheManager antiSamyCacheManager ,
			ShiroAntisamyProperties properties){
		FilterRegistrationBean<HttpServletRequestAntisamyFilter> registration = new FilterRegistrationBean<HttpServletRequestAntisamyFilter>();
		HttpServletRequestAntisamyFilter antisamyFilter = new HttpServletRequestAntisamyFilter(antiSamyCacheManager, properties);
		registration.setFilter(antisamyFilter);
	    registration.setEnabled(false); 
	    return registration;
	}

}
