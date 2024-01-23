package com.study.securityjwt.config;

import com.study.securityjwt.jwt.JWTFilter;
import com.study.securityjwt.jwt.LoginFilter;
import com.study.securityjwt.util.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // AuthenticationConfiguraion 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;

    // JWTUtil 생성자 주입
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    // AuthenticationManager 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    // BCryptPaasswordEncoder 등록
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf disable
        http
                .csrf((auth) -> auth.disable());

        // From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        // http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        // 필터 등록
        http    
                // 해당 필터 이전에 수행 (수행 할 필터, 기준 필터)
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        http
                // 해당 필터 자리에서 수행 (수행 할 필터, 대체 필터 자리)
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration),jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정 (JWT를 통한 인증/인가를 위해서 세션을 STATELESS 상태로 설정)
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // CORS 설정
        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        // 3000번 포트 설정
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        // 모든 메서드 허용
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        // Credentials 설정을 하면 ture 설정
                        configuration.setAllowCredentials(true);
                        // 허용 헤더
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        // 허용 시간
                        configuration.setMaxAge(3600L);

                        // 헤더를 보낼 때 JWT 위해서 Authorization 포함
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                })));

        return http.build();
    }
}