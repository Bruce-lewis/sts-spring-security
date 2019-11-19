package com.atguigu.security.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class AppSpringSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	DataSource dataSource;

	// 授权
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests().antMatchers("/layui/**", "/index.jsp").permitAll() // 设置匹配的资源放行
//				.antMatchers("/level2/*").hasAnyRole("ADMIN", "MANAGER")
//				.antMatchers("/level3/*").hasAnyAuthority("USER")
				.anyRequest().authenticated(); // 剩余任何资源必须认证

		http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {

			@Override
			public void handle(HttpServletRequest arg0, HttpServletResponse arg1, AccessDeniedException arg2)
					throws IOException, ServletException {
				// TODO Auto-generated method stub
				arg0.setAttribute("errorMsg", "对不起，您没有访问权限");
				arg0.getRequestDispatcher("/WEB-INF/views/unauthed.jsp").forward(arg0, arg1);
			}
		});

		// 实验7-2：记住我 数据库版(服务器中持久化了 浏览器登录成功的token)
		JdbcTokenRepositoryImpl jdbcTokenRepositoryImpl = new JdbcTokenRepositoryImpl();
		jdbcTokenRepositoryImpl.setDataSource(dataSource);
		// 服务器重启 记住我功能不会失效，但是浏览器清空缓存的cookie，会失效
		http.rememberMe().tokenRepository(jdbcTokenRepositoryImpl);

		// http.formLogin(); //默认登录页
		http.formLogin().loginPage("/index.jsp") // 去到指定的登录页
				.loginProcessingUrl("/login").usernameParameter("loginacct").passwordParameter("userpswd")
				// .successForwardUrl("/main.html");//成功后转发
				.successHandler(new AuthenticationSuccessHandler() {

					@Override
					public void onAuthenticationSuccess(HttpServletRequest arg0, HttpServletResponse arg1,
							Authentication arg2) throws IOException, ServletException {
						// TODO Auto-generated method stub
						arg1.sendRedirect(arg0.getContextPath() + "/main.html");
					}
				});

		http.logout().logoutUrl("/user-logout");

		// http.rememberMe();

		// 开启/禁用了csrf功能
		http.csrf().disable();

	}
	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	UserDetailsService userDetailsService;//用户详情查询服务组件的接口
	// 认证
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		// super.configure(auth);
		// 每一个用户必须拥有自己的权限信息
//		auth.inMemoryAuthentication().withUser("zhangsan").password("123456").roles("ADMIN").and().withUser("lisi")
//				.password("123123").authorities("USER", "MANAGER");
		
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	}
	@Bean
	public BCryptPasswordEncoder getBCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
