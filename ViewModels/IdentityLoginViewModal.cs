﻿namespace Identity1.ViewModels
{
    public class IdentityLoginRequestViewModal
    {
        
        public string? Email { get; set; }
        public string? Password { get; set; }
        public bool RememberMe { get; set; } = false;
    }

}
