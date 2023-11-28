package org.example.dao;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Repository
public class UserDao {

    // 在内存中存储应用程序的用户信息，这里只有一个用户
    private final static List<UserDetails> APPLICATION_USERS = Arrays.asList(
            new User(
                    "harukisea0@gmail.com", // 用户名
                    "password", // 密码
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")) // 用户角色
            )
    );

    // 根据用户邮箱查找用户
    public UserDetails findUserByEmail(String email){
        return APPLICATION_USERS
                .stream()
                .filter(u-> u.getUsername().equals(email)) // 使用 Lambda 表达式过滤用户
                .findFirst() // 返回第一个匹配的用户
                .orElseThrow(()->new UsernameNotFoundException("No user was found")); // 如果没有匹配的用户，则抛出异常
    }
}

