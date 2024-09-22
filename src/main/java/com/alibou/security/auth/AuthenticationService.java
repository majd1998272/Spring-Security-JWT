package com.alibou.security.auth;

import com.alibou.security.config.JwtService;
import com.alibou.security.user.Role;
import com.alibou.security.user.User;
import com.alibou.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

     //[Sign Up] : create new  user
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        User user = User.builder()
                .firstname(registerRequest.getFirstname())
                .lastname(registerRequest.getLastname())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        //create new token for new user
        var jwtToken = jwtService.generateToken(user);
        AuthenticationResponse generatedToken = AuthenticationResponse.builder()
                .accessToken(jwtToken).build();
        return generatedToken;
    }



    // [Log In ]  = [Sign In] :  check if user already exist and if exist generate token for him
//authentication manger that used method [authenticate] to authenticated user based on username and password
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword()
                ));// if the UserEmail or Password  not correct the will automatically  throw Exception


        //if the user  authenticated (Exist)  i will generate a token for him
        User user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        AuthenticationResponse generatedToken = AuthenticationResponse.builder()
                .accessToken(jwtToken).build();
        return generatedToken;
    }
}
