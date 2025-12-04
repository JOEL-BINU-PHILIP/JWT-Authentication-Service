package com.company.identity.controller.seller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/seller")
public class SellerController {

    @GetMapping("/products")
    public String sellerProducts() {
        return "Seller Products (Seller role required)";
    }
}
