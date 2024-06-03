package com.theme.starterkit.controllers;

import com.theme.starterkit.libs.KTTheme;
import com.theme.starterkit.libs.config.KTThemeBaseConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class DashboardController {
    @Autowired
    private KTTheme theme;

    @Autowired
    private KTThemeBaseConfig settings;

    @ModelAttribute
    public void init(@CookieValue(name="sidebar_minimize_state", required=false, defaultValue="off") String sidebarMinimizeState) {
        //keep sidebar minimize state for sidebar layouts
        if(settings.getDefaultLayout().contains("sidebar") && sidebarMinimizeState.equals("on")){
            theme.addHtmlAttribute("body", "data-kt-app-sidebar-minimize", "on");
            theme.addHtmlAttribute("sidebar-toggle", "data-kt-toggle-state", "active");
            theme.addHtmlClass("sidebar-toggle", "active");
        }
        theme.setLayout(settings.getDefaultLayout());
        theme.initLayout();
    }

    @GetMapping("/")
    public String index(){
        String[] vendors = {"amcharts", "amcharts-maps", "amcharts-stock"};
        theme.addVendors(vendors);
        return theme.getPageView("dashboards", "index");
    }
    
    @GetMapping("/contact")
    public String contact(Model model){
        String[] vendors = {"amcharts", "amcharts-maps", "amcharts-stock"};
        model.addAttribute("title","Contact");
        
        theme.addVendors(vendors);
        return theme.getPageView("apps/contact-management", "contact");
    }
    
    
}
