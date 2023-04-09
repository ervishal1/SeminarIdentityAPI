namespace Identity1.ViewModels
{
    public class ChangePassowrdRequest
    {
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ResetPasswordRequest
    {
        public string Token { get; set;}
        public string Email { get; set;}
        public string NewPassword { get; set;}
    }
}
