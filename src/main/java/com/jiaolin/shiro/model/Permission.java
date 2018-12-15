package com.jiaolin.shiro.model;

import lombok.Data;

/**
 * @program: shiro
 * @description: 权限
 * @author: Join
 * @create: 2018-12-10 22:30
 **/
@Data
public class Permission {
	private int pid;
	private String name;
	private String url;
}