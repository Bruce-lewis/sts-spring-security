package com.atguigu.security.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class AppSpringSecurityConfig实验8之前的配置类 extends WebSecurityConfigurerAdapter {
	//授权
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
		//super.configure(http);
		http.authorizeRequests()
		.antMatchers("/layui/**","/index.jsp").permitAll() //设置匹配的资源放行
		.anyRequest().authenticated(); //剩余任何资源必须认证
		
		
		//http.formLogin(); //默认登录页
		http.formLogin().loginPage("/index.jsp") //去到指定的登录页
			.loginProcessingUrl("/login")
			.usernameParameter("loginacct")
			.passwordParameter("userpswd")
			//.successForwardUrl("/main.html");//成功后转发
			.successHandler(new AuthenticationSuccessHandler() {
				
				@Override
				public void onAuthenticationSuccess(HttpServletRequest arg0, HttpServletResponse arg1, Authentication arg2)
						throws IOException, ServletException {
					// TODO Auto-generated method stub
					arg1.sendRedirect(arg0.getContextPath()+"/main.html");
				}
			});
		
		http.logout().logoutUrl("/user-logout");
		
		//开启/禁用了csrf功能
		http.csrf().disable();
		

	}
	
	//认证
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		//super.configure(auth);
		//每一个用户必须拥有自己的权限信息
		auth.inMemoryAuthentication()
		.withUser("zhangsan").password("123456").roles("ADMIN")
		.and()
		.withUser("lisi").password("123123").authorities("USER","MANAGER");
	}
}
