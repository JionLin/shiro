package com.jiaolin.shiro.config;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

/**
 * @program: shiro
 * @description: 密码比对器
 * @author: Join
 * @create: 2018-12-10 23:25
 **/
public class CredentialMatcher extends SimpleCredentialsMatcher {

    /**
     * @Description: 密码匹配器  token先转换成usernameToken,
     * @Param: [authenticationToken, authenticationInfo]
     * @return: boolean
     * @Author: Join
     * @Date: 2018/12/11
     */
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
        String password = String.valueOf(usernamePasswordToken.getPassword());
        String dbPassword = (String) info.getCredentials();
        return this.equals(password, dbPassword);
    }
}