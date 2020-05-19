package com.jeesoul.oauth2.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 服务器安全配置
 *
 * 其中注解@EnableGlobalMethodSecurity有几个方法：
 * <p>
 * prePostEnabled： 确定 前置注解[@PreAuthorize,@PostAuthorize,..] 是否启用
 * securedEnabled： 确定安全注解 [@Secured] 是否启用
 * jsr250Enabled： 确定 JSR-250注解 [@RolesAllowed..]是否启用
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    /**
     * 配置默认的加密方式
     *
     * @return
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 基于内存的
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 在内存中创建用户
        auth.inMemoryAuthentication()
                .withUser("admin").password(passwordEncoder().encode("123456")).roles("ADMIN")
                .and()
                .withUser("user").password(passwordEncoder().encode("111111")).roles("USER");

    }
}
