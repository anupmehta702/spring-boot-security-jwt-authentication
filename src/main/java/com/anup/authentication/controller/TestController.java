package com.anup.authentication.controller;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/all")
    public String allAccess() {
        System.out.println("Printing authorities -->"
                +SecurityContextHolder.getContext().getAuthentication().getAuthorities());
        return "Public Content.";
    }

    @GetMapping("/user")
    @PostAuthorize("hasAuthority('USER') or hasAuthority('MODERATOR') or hasAuthority('ADMIN')")//used hasAuthority instead of hasRole since spring version is 2.7
    public String userAccess() {
        System.out.println("Printing authorities -->"
                +SecurityContextHolder.getContext().getAuthentication().getAuthorities());

        return "User Content.";
    }

    @GetMapping("/admin")
    @PostAuthorize("hasAuthority('ADMIN')") //used hasAuthority instead of hasRole since spring version is 2.7
    public String adminAccess() {
        System.out.println("Printing authorities -->"
                +SecurityContextHolder.getContext().getAuthentication().getAuthorities());
        return "Admin Content.";
    }


    @GetMapping("/mod")
    @PostAuthorize("hasAuthority('MODERATOR')")
    public String modAccess() {
        return "Moderator Content.";
    }


}
