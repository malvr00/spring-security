package com.cos.security1.config.auth;

import com.cos.security1.domain.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

// 시큐리티 설정에서 loginProcessingUrl("/login");일 경우
// login 요청이 오면 자동으로 UserDetailsService 타입으로 ioC되어 있는 loadUserByUsername 함수가 실행
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // User정보에 username으로 값이 들어와야 매칭이 됨.
    // username으로 들어 오지 않는다면 SecurityConfig(.usernameParameter("username2"))에서 username으로 매칭 되는 값을 따로 설정 해 줘야함
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("username : " + username);
        User user = userRepository.findByUsername(username);
        if(user != null){
            // return 된 값이 Authentication 내부에 들어감. 그 다음 security session 내부로 들어감.
            // 결과 => security session(Authentication(PrincipalDetails))
            return new PrincipalDetails(user);
        }
        return null;
    }
}
