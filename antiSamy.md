
# web应用 配置 

> 依赖包

<dependency>
	<groupId>org.owasp.antisamy</groupId>
	<artifactId>antisamy</artifactId>
	<version>最新版本 Maven 为准</version>
</dependency>
<dependency>
    <groupId>com.jeefw</groupId>
    <artifactId>jeekit-lang3</artifactId>
    <version>最新版本 Maven 为准</version>
</dependency>
<dependency>
    <groupId>com.jeefw</groupId>
    <artifactId>jeekit-io</artifactId>
    <version>最新版本 Maven 为准</version>
</dependency>
<dependency>
    <groupId>com.jeefw</groupId>
    <artifactId>jeekit-collections</artifactId>
    <version>最新版本 Maven 为准</version>
</dependency>
<dependency>
    <groupId>com.jeefw</groupId>
    <artifactId>jeeweb-core</artifactId>
    <version>最新版本 Maven 为准</version>
</dependency>

> web.xml 配置

<!-- 防XSS攻击过滤器 -->
<filter>
	<filter-name>xssFilter</filter-name>
	<filter-class>com.jeefw.safety.xss.HttpServletRequestXssFilter</filter-class>
	<!-- 扫描器类型，0：DOM类型扫描器,1:SAX类型扫描器；两者的区别如同XML解析中DOM解析与Sax解析区别相同，实际上就是对两种解析方式的实现 -->
    <init-param>
    	<param-name>scanType</param-name>
    	<param-value>1</param-value>
    </init-param>
	<!-- 请求路径的正则匹配表达式，匹配的路径会被检测XSS;多个表达式可以用",; \t\n"中任意字符分割  -->
    <init-param>
    	<param-name>includePatterns</param-name>
    	<param-value>*.do</param-value>
    </init-param>
    <!-- 不进行过滤请求路径的正则匹配表达式，匹配的路径不会被检测XSS;多个表达式可以用",; \t\n"中任意字符分割 -->
    <init-param>
    	<param-name>excludePatterns</param-name>
    	<param-value>/a/*.do,/b/*.do</param-value>
    </init-param>
    <!-- 默认的防XSS攻击的规则配置-->
    <init-param>
    	<param-name>defaultPolicy</param-name>
    	<param-value>classpath:antisamy-default.xml</param-value>
    </init-param>
    <!-- 防XSS攻击的模块对应的规则配置；每个模块表达式与规则文件使用"|"分割；多个配置可以用",; \t\n"中任意字符分割 -->
    <init-param>
    	<param-name>policyMappings</param-name>
    	<param-value>/manager/*|manager-antixss-policy.xml,/guest/*|guest-antixss-policy.xml</param-value>
    </init-param>
    <!-- 使用 x.properties文件来配置防XSS攻击时相关参数的配置文件路径-->
    <init-param>
    	<param-name>configLocation</param-name>
    	<param-value>antisamy.properties</param-value>
    </init-param>
</filter>
<filter-mapping>
	<filter-name>xssFilter</filter-name>
	<url-pattern>*.do</url-pattern>
</filter-mapping>




