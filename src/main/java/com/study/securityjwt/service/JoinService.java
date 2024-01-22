package com.study.securityjwt.service;

import com.study.securityjwt.dto.JoinDto;
import com.study.securityjwt.entity.UserEntity;
import com.study.securityjwt.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {

        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    // 회원 가입 기능
    public void joinProcess(JoinDto joinDto) {

        // dto 입력
        String username = joinDto.getUsername();
        String password = joinDto.getPassword();

        // 존재 여부 확인
        Boolean isExist = userRepository.existsByUsername(username);

        // 존재하는 경우
        if (isExist) return;

        UserEntity data = new UserEntity();

        // 유저 저장
        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}