package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨.
public class SecurityConfig {

    /*
기존: WebSecurityConfigurerAdapter를 상속하고 configure매소드를 오버라이딩하여 설정하는 방법
=> 현재: SecurityFilterChain을 리턴하는 메소드를 빈에 등록하는 방식(컴포넌트 방식으로 컨테이너가 관리)
//https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter

@Override
protected void configure(HttpSecurity http) throws  Exception{
http.csrf().disable();
http.authorizeRequests()
        .antMatchers("/user/**").authenticated()
        .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
        .antMatchers("/admin").access("\"hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll();
}

*/

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                // /user/** 들어오면 인증이 필요하다는 선언
                .antMatchers("/user/**").authenticated()
                // /manager/** login은 했지만 manager나 admin인 권한 만 접속 가능
                .antMatchers("/manager/**").access("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
                // /admin/** admin인 권한 만 접속 가능
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                // 저 위에 선언한 것을 제외한 모든 권한 허용, /login uri 시큐리티 로그인 페이지로 낚아채지던 현상 없애 버림.
                .anyRequest().permitAll()
                .and()
                // 권한 필요한 설정 일 경우 login 페이지로 강제 이동 시킴.
                .formLogin()
                .loginPage("/loginForm");

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder encodePwd(){
        // 프레임워크에서 제공하는 클래스 중 하나로 비밀번호를 암호화하는 데 사용할 수 있는 메서드를 가진 클래스.
        return new BCryptPasswordEncoder();
    }

}
