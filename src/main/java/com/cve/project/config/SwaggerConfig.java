package com.cve.project.config;

import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;

@Configuration
@OpenAPIDefinition(
		info = @Info(
				title = "CVE OPEN API",
				version = "v3",
				description = "This is a sample API for retrieve cve based on requirenment."
				)
		)
public class SwaggerConfig {

}
