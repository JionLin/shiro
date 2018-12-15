package com.jiaolin.shiro.mapper;

import com.jiaolin.shiro.model.User;

/**
 * @program: shiro
 * @description: 用户mapper
 * @author: Join
 * @create: 2018-12-10 22:41
 **/
public interface UserMapper {
	User findUserByUsername(String username);
}
