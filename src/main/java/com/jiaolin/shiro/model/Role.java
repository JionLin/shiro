package com.jiaolin.shiro.model;

import lombok.Data;

import java.util.HashSet;
import java.util.Set;

/**
 * @program: shiro
 * @description: 角色
 * @author: Join
 * @create: 2018-12-10 22:29
 **/
@Data
public class Role {
	private int rid;
	private String rname;
	private Set<User> userSet = new HashSet<>();
	private Set<Permission> permissions = new HashSet<>();
}