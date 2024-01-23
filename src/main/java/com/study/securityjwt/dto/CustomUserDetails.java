package com.study.securityjwt.dto;

import com.study.securityjwt.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class CustomUserDetails implements UserDetails {

    private final UserEntity userEntity;

    public CustomUserDetails(UserEntity userEntity) {
        this.userEntity = userEntity;
    }

    // Role 반환
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {
                return userEntity.getRole();
            }
        });

        return collection;
    }

    // 암호 반환
    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    // 아이디 반환
    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }

    // 계정 만료 여부 반환
    @Override
    public boolean isAccountNonExpired() {
        
        // 만료 X
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {

        // 잠금 X
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {

        // 자격 증명 유효
        return true;
    }

    @Override
    public boolean isEnabled() {

        // 사용 가능
        return true;
    }
}