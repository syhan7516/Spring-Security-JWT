package com.study.securityjwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {

        // 모든 컨트롤러에서 해당 주소에서 오는 요청 허용
        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:3000");
    }
}