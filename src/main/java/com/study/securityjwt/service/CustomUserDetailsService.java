package com.study.securityjwt.service;

import com.study.securityjwt.dto.CustomUserDetails;
import com.study.securityjwt.entity.UserEntity;
import com.study.securityjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 회원 조회
        UserEntity userData = userRepository.findByUsername(username);

        // 회원이 존재하는 경우
        if (userData != null) {

            // AutneticationManager 검증을 위해 UserDetails 담아 반환
            return new CustomUserDetails(userData);
        }

        return null;
    }
}