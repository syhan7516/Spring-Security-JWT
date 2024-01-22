package com.study.securityjwt.repository;

import com.study.securityjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    
    // 유저 존재 여부
    Boolean existsByUsername(String username);
}