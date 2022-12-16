package com.cos.security1.config.auth;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행.
// 로그인 진행이 완료가 되면 시큐리티 session을 만들어줌. (시큐리티 자신만의 session 공간에 Security ContextHolder을 가져서 거기서에 만들어 짐)
// Security ContextHolder 들어 갈수 있는 오브젝트가 있음. => Authentication 타입 객체
// Authentication 안에 User정보가 있어야 됨.
// User 오브젝트 타입 => UserDetails 타입 객체여야 함.

// Security Session => Authentication => UserDetails(PrincipalDetails)

import com.cos.security1.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipalDetails implements UserDetails {

    private User user; // 콤포지션

    public PrincipalDetails(User user){
        this.user = user;
    }

    // 해당 User의 권한을 리턴 하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        // 우리 사이트에서 1년동안 회원이 로그인을 안하면, 휴먼 계정으로 하기로 함.
        // 현재시간 - 로그인 시간 => 1년을 초과하면 return false;
        return true;
    }
}
