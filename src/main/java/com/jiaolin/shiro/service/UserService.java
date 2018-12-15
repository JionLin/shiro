package com.jiaolin.shiro.service;

import com.jiaolin.shiro.model.User;

/**
 * @program: shiro
 * @description: 用户service
 * @author: Join
 * @create: 2018-12-10 23:08
 **/
public interface UserService {
	User findUserByUsername(String name);
}
