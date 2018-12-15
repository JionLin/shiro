package com.jiaolin.shiro.config;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;

/**
 * @program: shiro
 * @description: shiro配置
 * @author: Join
 * @create: 2018-12-10 23:22
 **/
@Configuration
public class ShiroConfig {
    //有6个方法
    // 1 密码比较器
    //2 realm 认证
    //3 安全管理器
    //4 shiro拦截器 进行配置
    //5 需要进行配置shiro注解和aop联合
    //6 需要配置和spring代理
    //配置好后还需要设置密码验证 TODO

    /**
     * @Description: DefaultFilter 默认拦截器对应的类
     * anon(AnonymousFilter.class), 匿名访问
     * authc(FormAuthenticationFilter.class), 表示需要认证才能使用
     * authcBasic(BasicHttpAuthenticationFilter.class),
     * logout(LogoutFilter.class), 登出
     * noSessionCreation(NoSessionCreationFilter.class),
     * perms(PermissionsAuthorizationFilter.class), 权限
     * /admins/user/**=perms[user:add:*],perms参数可以写多个，多个时必须加上引号，
     * 并且参数之间用逗号分割，例如/admins/user/**=perms["user:add:*,user:modify:*"]，
     * 当有多个参数时必须每个参数都通过才通过，想当于isPermitedAll()方法。
     * port(PortFilter.class), port 请求的端口号
     * rest(HttpMethodPermissionFilter.class),
     * roles(RolesAuthorizationFilter.class), 角色
     * roles：例子/admins/user/**=roles[admin],参数可以写多个，多个时必须加上引号，
     * 并且参数之间用逗号分割，当有多个参数时，例如/admins/user/**=roles["admin,guest"],
     * 每个参数通过才算通过，相当于hasAllRoles()方法。
     * ssl(SslFilter.class),
     * user(UserFilter.class); 需要用户登录才能 user：例如/admins/user/**=user没有参数
     * 表示必须存在用户，当登入操作时不做检查
     * @Param: [securityManager]
     * @return: org.apache.shiro.spring.web.ShiroFilterFactoryBean
     * @Author: Join
     * @Date: 2018/12/11
     */
    @Bean("shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(@Qualifier("securityManager") SecurityManager securityManager) {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(securityManager);
        bean.setLoginUrl("/login");
        bean.setSuccessUrl("/index");
        bean.setUnauthorizedUrl("/unauthorized");
        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        filterChainDefinitionMap.put("/index", "authc");
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/loginUser", "anon");
        //角色为admin的用户才能访问admin网页
        filterChainDefinitionMap.put("/admin", "roles[admin]");
//        filterChainDefinitionMap.put("/admin", "roles[admin]");
        //权限为edit的角色才能访问edit页面
        filterChainDefinitionMap.put("/edit", "perms[edit]");
        filterChainDefinitionMap.put("/druid/**", "anon");
        //另外的页面需要用户进行登录才能访问
        filterChainDefinitionMap.put("/**", "user");
        bean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return bean;
    }

    /**
     * @Description: 回话管理
     * @Param: [authRealm]
     * @return: org.apache.shiro.mgt.SecurityManager
     * @Author: Join
     * @Date: 2018/12/11
     */
    @Bean("securityManager")
    public SecurityManager securityManager(@Qualifier("authRealm") AuthRealm authRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(authRealm);
        return securityManager;
    }

    /**
     * @Description: Realm 认证过程  bean指的是一个方法上面的验证,配合compont和configuration使用
     * @Param: [credentialMatcher]
     * @return: com.jiaolin.shiro.config.AuthRealm
     * @Author: Join
     * @Date: 2018/12/11
     */
    @Bean("authRealm")
    public AuthRealm authRealm(@Qualifier("credentialMatcher") CredentialMatcher credentialMatcher) {
        AuthRealm authRealm = new AuthRealm();
        authRealm.setCredentialsMatcher(credentialMatcher);
        return authRealm;
    }

    /**
     * @Description: 密码匹配器
     * @Param: []
     * @return: com.jiaolin.shiro.config.CredentialMatcher
     * @Author: Join
     * @Date: 2018/12/11
     */
    @Bean("credentialMatcher")
    public CredentialMatcher credentialMatcher() {
        return new CredentialMatcher();
    }


    /**
     * @Description: 配置注解和spring的整合
     * @Param: [securityManager]
     * @return: org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor
     * @Author: Join
     * @Date: 2018/12/11
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor advisor(@Qualifier("securityManager") SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor sourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        sourceAdvisor.setSecurityManager(securityManager);
        return sourceAdvisor;
    }

    /** 
    * @Description: 设置自动代理
    * @Param: [] 
    * @return: org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator 
    * @Author: Join
    * @Date: 2018/12/11 
    */
    @Bean
    public DefaultAdvisorAutoProxyCreator proxyCreator() {
        DefaultAdvisorAutoProxyCreator proxyCreator = new DefaultAdvisorAutoProxyCreator();
        proxyCreator.setProxyTargetClass(true);
        return proxyCreator;
    }
}