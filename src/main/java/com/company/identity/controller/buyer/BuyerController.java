package com.company.identity.controller.buyer;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/buyer")
public class BuyerController {

    @GetMapping("/orders")
    public String buyerOrders() {
        return "Buyer Orders (Buyer role required)";
    }
}
