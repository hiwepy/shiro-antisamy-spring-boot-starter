package org.apache.shiro.spring.boot.antisamy.cache;

/**
 * 
 * *******************************************************************
 * @className	： AntiSamyKey
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date		： Mar 31, 2016 1:49:51 PM
 * @version 	V1.0 
 * *******************************************************************
 */
public abstract class AntiSamyKey {

	/** 多个配置的情况下的分割符号*/
	public final static String  MODULE_SPLIT_KEY = "moduleSplit";
	/** 解析扫描器类型取值key*/
	public final static String SCANTYPE_KEY = "scanType";
	/** 需要过滤的请求路径的正则匹配表达式取值key*/
	public final static String INCLUDE_PATTERNS_KEY = "includePatterns";
	/** 不需要过滤的请求路径的正则匹配表达式取值key*/
	public final static String EXCLUDE_PATTERNS_KEY = "excludePatterns";
	/** 默认的防XSS攻击的规则配置取值key*/
	public final static String DEFAULT_POLICY_KEY = "defaultPolicy";
	/** 防XSS攻击的模块对应的规则配置取值key*/
	public final static String  POLICY_MAPPINGS_KEY = "policyMappings";
	/** 使用 x.properties文件来配置防XSS攻击时相关参数的配置文件路径 */
	public final static String  CONFIG_LOCATION_KEY = "configLocation";
	
}
