package com.tms.springsecurity.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class HomeController {

    @GetMapping(path = "/user")
    public String user(){
        return "user.html";
    }

    @GetMapping(path = "/admin")
    public String admin(){
        return "admin.html";
    }

}
