package com.nelioalves.cursomc.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment env;

	private static final String[] PUBLIC_MATCHERS = { "/h2-console/**" };
	private static final String[] PUBLIC_MATCHERS_GET = { "/produtos/**", "/categorias/**",  "/clientes/**" };

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// Para acessar o H2, somente ambiente de teste
		if (Arrays.asList(env.getActiveProfiles()).contains("test")) {
			http.headers().frameOptions().disable();
		}

		http.cors().and().csrf().disable();

		http.authorizeRequests()
				// permite accesso somente de GET a todas que estiverem em: PUBLIC_MATCHERS_GET
				.antMatchers(HttpMethod.GET, PUBLIC_MATCHERS_GET).permitAll()
				// permite accesso qualquer funcionalidade a todas que estiverem em:
				// PUBLIC_MATCHERS
				.antMatchers(PUBLIC_MATCHERS).permitAll()
				// Para todo o restante, tem que se autenticar
				.anyRequest().authenticated();

		// Para garantir que não seja criada sessões pelo usuário
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {

		/*
		 * CorsConfiguration configuration = new CorsConfiguration();
		 * configuration.setAllowedMethods(List.of( HttpMethod.GET.name(),
		 * HttpMethod.PUT.name(), HttpMethod.POST.name(), HttpMethod.DELETE.name() ));
		 */
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
		return source;
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
