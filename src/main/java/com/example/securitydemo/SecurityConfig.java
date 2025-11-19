package com.example.securitydemo;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.securitydemo.jwt.AuthEntryPointJwt;
import com.example.securitydemo.jwt.AuthTokenFilter;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity 
public class SecurityConfig {

    private final AuthTokenFilter authenticationJwtAuthTokenFilter;
	
	@Autowired
	DataSource dataSource;
	
	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;

    SecurityConfig(AuthTokenFilter authenticationJwtAuthTokenFilter) {
        this.authenticationJwtAuthTokenFilter = authenticationJwtAuthTokenFilter;
    }
	
	
	// public AuthTokenFilter authenticationJwtAuthTokenFilter() {
	// 	return new AuthTokenFilter();
	// }
	
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
		http.authorizeHttpRequests((authorizeRequests) ->
		authorizeRequests.requestMatchers("/h2-console/**").permitAll()
		.requestMatchers("/signin").permitAll()
		.anyRequest().authenticated());
		http.sessionManagement(session ->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//		http.formLogin(withDefaults());
//		http.httpBasic(withDefaults());
		http.exceptionHandling( exception ->
		exception.authenticationEntryPoint(unauthorizedHandler)
			);
		
		http.headers(headers -> headers.frameOptions(frameOptions->frameOptions.sameOrigin()));
		http.csrf(csrf ->csrf.disable());
		
		http.addFilterBefore(authenticationJwtAuthTokenFilter,
				UsernamePasswordAuthenticationFilter.class);
		
		return http.build();
		
	}
	
	
//	@Bean
//	public UserDetailsService userDetailsService() {
//		UserDetails user1 =User.withUsername("user1")
//				.password(passwordEncoder().encode("password1"))
//				.roles("USER")
//				.build();
//		
//		UserDetails admin=User.withUsername("admin")
//				.password(passwordEncoder().encode("adminpass"))
//				.roles("ADMIN")
//				.build();
//		
//		JdbcUserDetailsManager userDetailsManager 
//		=new JdbcUserDetailsManager(dataSource);
//		userDetailsManager.createUser(user1);
//		userDetailsManager.createUser(admin);
//		return userDetailsManager;
////	return new InMemoryUserDetailsManager(user1, admin);
//		
//	}
	
	
	public UserDetailsService userDetailsService (DataSource dataSource) {
	return new JdbcUserDetailsManager (dataSource);
	}
	
	
	public CommandLineRunner initData (UserDetailsService userDetailsService) {

	return args -> {
	JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
	UserDetails userl = User.withUsername ("user1")
			.password (passwordEncoder().encode("password1"))
			.roles ("USER")
			.build();

	UserDetails admin = User.withUsername ("admin")
			
			//.password (passwordEncoder().encode ("adminPass"))

			.password (passwordEncoder().encode("adminPass"))
			.roles ("ADMIN")
			.build();

			JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager (dataSource);
			userDetailsManager.createUser (userl);
			userDetailsManager.createUser (admin);
	
	};
	}
	
	
	

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
		
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
		return builder.getAuthenticationManager();
	}
	

}
