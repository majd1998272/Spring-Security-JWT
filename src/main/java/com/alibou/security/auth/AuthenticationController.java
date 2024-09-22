package com.alibou.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    //create new user and generate token for him
    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody RegisterRequest registerRequest){
        try {
            // return AuthenticationResponse
            AuthenticationResponse newUserToken =  authenticationService.register(registerRequest);
            return new  ResponseEntity<>(newUserToken,HttpStatus.OK);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FAILED_DEPENDENCY).body(e.getMessage());
        }
    }



    @PostMapping("/authenticate")
    public ResponseEntity<Object> authenticate(@RequestBody AuthenticationRequest authenticationRequest){
        try {
            AuthenticationResponse alreadyUserToken =  authenticationService.authenticate(authenticationRequest);

            return new  ResponseEntity<>(alreadyUserToken,HttpStatus.OK);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FAILED_DEPENDENCY).body(e.getMessage());
        }
    }


}
