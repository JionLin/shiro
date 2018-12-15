package com.jiaolin.shiro.config;

import com.jiaolin.shiro.model.Permission;
import com.jiaolin.shiro.model.Role;
import com.jiaolin.shiro.model.User;
import com.jiaolin.shiro.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @program: shiro
 * @description: 自定义认证器
 * @author: Join
 * @create: 2018-12-10 23:24
 **/
public class AuthRealm extends AuthorizingRealm {

	@Autowired
	private UserService userService;

	/**
	 * @Description: 授权 1 拿到对应的用户,根据用户拿到角色(admin,customer)
	 * 和权限的名字(增删改查)
	 * @Param: [principalCollection]
	 * @return: org.apache.shiro.authz.AuthorizationInfo
	 * @Author: Join
	 * @Date: 23:26
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principal) {
		User user = (User) principal.fromRealm(this.getClass().getName()).iterator().next();
		Set<Role> roles = user.getRoles();
		List<String> roleList = new ArrayList<>();
		List<String> permissionList = new ArrayList<>();
		if (!CollectionUtils.isEmpty(roles)) {
			for (Role role : roles) {
				roleList.add(role.getRname());
				Set<Permission> permissions = role.getPermissions();
				if (!CollectionUtils.isEmpty(permissions)) {
					for (Permission permission : permissions) {
						permissionList.add(permission.getName());
					}
				}
			}
		}
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRoles(roleList);
		info.addStringPermissions(permissionList);
		return info;
	}

	/**
	 * @Description: 认证
	 * @Param: [authenticationToken]
	 * @return: org.apache.shiro.authc.AuthenticationInfo
	 * @Author: Join
	 * @Date: 23:26
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
		String username = usernamePasswordToken.getUsername();
		User user = userService.findUserByUsername(username);
		return new SimpleAuthenticationInfo(user, user.getPassword(), this.getClass().getName());
	}




	public static void main(String[] args) {
		String hashAlgorithmName = "MD5";
		String credentials = "123456";
		int hashIterations = 1024;
		Object obj = new SimpleHash(hashAlgorithmName, credentials, null,hashIterations);
		System.out.println(obj);
	}
}