package com.jiaolin.shiro.controller;

import com.jiaolin.shiro.model.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpSession;

/**
 * @program: shiro
 * @description: 用户web层
 * @author: Join
 * @create: 2018-12-10 23:11
 **/
@Controller
public class UserController {

    /**
     * @Description: 用户登录 登录成功返回index 失败跳转到login
     * @Param: [username, password]
     * @return: java.lang.String
     * @Author: Join
     * @Date: 23:13
     */
    @RequestMapping("/loginUser")
    public String login(@RequestParam("username") String username,
                        @RequestParam("password") String password, HttpSession session) {
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(token);
            //获取主体
            User user = (User) subject.getPrincipal();
            //并设置在session中
            session.setAttribute("user", user);
            return "index";
        } catch (Exception e) {
            e.printStackTrace();
            return "login";
        }
    }

    /**
     * @Description: 跳转登录页面
     * @Param: []
     * @return: java.lang.String
     * @Author: Join
     * @Date: 23:20
     */
    @RequestMapping("/login")
    public String login() {
        return "login";
    }

    /**
     * @Description: admin登录成功
     * @Param: []
     * @return: java.lang.String
     * @Author: Join
     * @Date: 23:20
     */
    @RequestMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin success";
    }


    /**
     * @Description: 跳转到index页面
     * @Param: []
     * @return: java.lang.String
     * @Author: Join
     * @Date: 23:20
     */
    @RequestMapping("/index")
    public String index() {
        return "index";
    }

    /**
     * @Description: 登出
     * @Param: []
     * @return: java.lang.String
     * @Author: Join
     * @Date: 23:14
     */
    @RequestMapping("/logout")
    public String logout() {
        Subject subject = SecurityUtils.getSubject();
        if (subject != null) {
            subject.logout();
        }
        return "login";
    }

    /**
     * @Description: 授权不成功跳转页面
     * @Param: []
     * @return: java.lang.String
     * @Author: Join
     * @Date: 23:19
     */
    @RequestMapping("/unauthorized")
    public String unauthorized() {
        return "unauthorized";
    }

    /**
     * @Description: 编辑成功
     * @Param: []
     * @return: java.lang.String
     * @Author: Join
     * @Date: 23:18
     */
    @RequestMapping("/edit")
    @ResponseBody
    public String edit() {
        return "edit success";
    }
}