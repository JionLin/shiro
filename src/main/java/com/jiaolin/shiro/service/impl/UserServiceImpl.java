package com.jiaolin.shiro.service.impl;

import com.jiaolin.shiro.mapper.UserMapper;
import com.jiaolin.shiro.model.User;
import com.jiaolin.shiro.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @program: shiro
 * @description:
 * @author: Join
 * @create: 2018-12-10 23:09
 **/
@Service
public class UserServiceImpl implements UserService {
	@Autowired
	private UserMapper userMapper;

	@Override
	public User findUserByUsername(String name) {
		return userMapper.findUserByUsername(name);
	}
}