package com;

import java.security.Principal;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.Message;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@SpringBootApplication
public class CustomAuthenticationExampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(CustomAuthenticationExampleApplication.class, args);
	}

}

@Configuration
@EnableWebSecurity
class SecurityConfig{
	
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		http
//			.cors(x->x.disable())
			.csrf(x->x.disable())
			.authorizeHttpRequests(x->{
					x.requestMatchers("user/login", "user/principal", "user/logout").permitAll();
				x.requestMatchers(PathRequest.toH2Console()).permitAll();
				x.anyRequest().authenticated();
			})
			.headers(x->x.frameOptions(y->y.sameOrigin()))
			;
		
		return http.build();
	}
	
	@Bean
	AuthenticationProvider authenticationProvider() {
		
		return new AuthenticationProvider() {
			
			@Override
		    public Authentication authenticate(Authentication auth) throws AuthenticationException {
				
				System.err.println("authenticating with custom provider...");
				
		        String username = auth.getName();
		        String password = auth.getCredentials().toString();

		        if ("sam".equals(username) && "liew".equals(password)) {
		        	UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password, AuthorityUtils.createAuthorityList("ADMIN"));
		        	SecurityContextHolder.getContext().setAuthentication(token);
		        	return token;
		        }
		        else
		        	throw new BadCredentialsException("Custom Authentication Provider Failed");
		    }

		    @Override
		    public boolean supports(Class<?> auth) {
		        return auth.equals(UsernamePasswordAuthenticationToken.class);
		    }
			
		};
	}
	
	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}

@RestController
@RequestMapping("user")
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
class UserController{
	
	@Autowired
	AuthenticationManager authManager;
	
	@Autowired
	PasswordEncoder encoder;
	
	@PostMapping("login")
	public ResponseEntity<?> login(@RequestBody Map map, HttpServletRequest request) throws Exception{
		
		String username = (String) map.get("username");
		String password = (String) map.get("password");
		
		Authentication token = new UsernamePasswordAuthenticationToken(username, password);
		authManager.authenticate(token);
//		
//		// this is what allows server to subsequently identify user.
		HttpSession session = request.getSession(true);
		session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
		
		// can be shorten to 
//		request.login(username,password);
		
		return ResponseEntity.ok("login successful");
	}
	
	@PostMapping("logout")
	public void logout(HttpServletRequest request) throws ServletException {
		SecurityContextHolder.clearContext();
		
		HttpSession session = request.getSession(false);
		if (session != null)
			session.invalidate();
		
//		request.logout();
		
		System.err.println("logout completed");
	}
	
	
	@GetMapping("principal")
	public ResponseEntity<?> principal(Principal principal, HttpServletRequest request){
		
		try {
			HttpSession session = request.getSession(false);
			if(session != null)
				System.err.println("session="+session.getId());
			else
				System.err.println("session is null");
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		return ResponseEntity.ok(principal == null ? "principal == null" : "principal != null ("+principal.getName()+")");
	}
	
}

@Configuration
@EnableWebSocket
@EnableWebSocketSecurity
class WebSocketConfig implements WebSocketConfigurer{

	@Autowired
	MyWebSocketHandler handler;
	
	@Override
	public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
		// TODO Auto-generated method stub
		registry.addHandler(handler, "websocket")
			.setAllowedOrigins("http://localhost:5173")
			;
	}
	
	@Bean
    AuthorizationManager<Message<?>> messageAuthorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
        messages
                .anyMessage()
                	.authenticated()
//                .permitAll()
                ;

        return messages.build();
    }
}

@Component
class MyWebSocketHandler extends TextWebSocketHandler{
	
	@Override
	public void afterConnectionEstablished(WebSocketSession session) throws Exception {
		// TODO Auto-generated method stub
		try {
			Principal principal = session.getPrincipal();
			System.err.println("conn established with principal="+principal.getName());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.err.println("principal is null");
			session.close();
		}
	}
	
}