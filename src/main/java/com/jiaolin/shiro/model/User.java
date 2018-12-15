package com.jiaolin.shiro.model;

import lombok.Data;

import java.util.HashSet;
import java.util.Set;

/**
 * @program: shiro
 * @description: 用户
 * @author: Join
 * @create: 2018-12-10 22:29
 **/
@Data
public class User {
	private int uid;
	private String username;
	private String password;
	private Set<Role> roles = new HashSet<>();
}