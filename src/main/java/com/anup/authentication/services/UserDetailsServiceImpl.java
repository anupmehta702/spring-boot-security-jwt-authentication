package com.anup.authentication.services;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {


    //currently getting static details
    //need to send USerDetails String object since we need to create Authentication object
    // that we can set in SecurityContextHolder.setDetails(authentication)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(getUserDetails().containsKey(username)) {
            return getUserDetails().get(username);
        }
        throw new UsernameNotFoundException("Username - "+username+" not present !");
    }

    //TODO need to replace this with database call
    public HashMap<String,UserDetails> getUserDetails(){
        HashMap<String,UserDetails> userDetailsMap = new HashMap<>();
        userDetailsMap.put("anup",getUser("anup","anup","ADMIN"));
        userDetailsMap.put("akash",getUser("akash","akash","USER"));
        userDetailsMap.put("rahul",getUser("rahul","rahul","MODERATOR"));
        return userDetailsMap;
    }

    private User getUser(String username,String password,String role){
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(role));
        return new User(username,password,roles);
    }
}
