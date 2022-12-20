package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.domain.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository userRepo;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    // authentication DI (의존성 주읩)
    // @AuthenticationPrincipal 세션 정보에 접근 가능 ( UserDetails )
    public @ResponseBody String testLogin(Authentication authentication,
                                          @AuthenticationPrincipal PrincipalDetails userDetails){
        System.out.println("/test/login =================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        System.out.println("authentication.getPrincipal() = " + principalDetails.getUser());
        System.out.println("UserDetails:" + userDetails.getUser());

        return "세선 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User oAuth2User2){
        System.out.println("/test/oauth/login =================");
        OAuth2User oAuth2User1 = (OAuth2User) authentication.getPrincipal();

        System.out.println("oAuth2User = " + oAuth2User1.getAttributes());
        System.out.println("oAuth2User = " + oAuth2User2.getAttributes());

        return "OAuth 세선 정보 확인하기";
    }

    @GetMapping({"","/"})
    public String index(){
        // View는 머스테치 사용
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(){
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    // 스프링시큐리티가 해당 주소를 낚아챔.
//    @GetMapping("/login")
//    public String login(){
//        return "loginForm";
//    }

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String JoinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user){
        System.out.println(user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepo.save(user);
        return "redirect:/loginForm";
    }

    // ******************* EnableGlobalMethodSecurity 설정 해야 Secured, PostAuthorize, PreAuthorize 사용 가능 ****************//
    // 단일 설정 할 때 사용.
    @Secured("ROLL_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "정보보기";
    }

    // 다수 권한 설정 할때 사용
    @PreAuthorize("hasRole('ROLL_ADMIN') or hasRole('ROLL_MANAGER')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터";
    }

}
