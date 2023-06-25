namespace Identity1.ViewModels
{
    public class ApplicationUserResponse
    {
        public string Id { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? ProfileImg { get; set; } = string.Empty;
        public bool? EmailConfirmed { get; set; }
        public bool? TwoFactorEnabled { get; set; }
        public IList<string>? Roles { get; set; }
        public DateTime? CreatetAt { get; set; }

    }
}
