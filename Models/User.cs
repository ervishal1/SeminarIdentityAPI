using System.ComponentModel.DataAnnotations;

namespace Identity1.Models
{
    public class User
    {
        [Required]
        public string? Name { get; set; }
        [Required]
        [EmailAddress(ErrorMessage ="Invalid Email")]
        public string? Email { get; set; }
        [Required, DataType(DataType.Password)]
        public string? Password { get; set; }
        [Required, DataType(DataType.Password),Compare(nameof(Password),ErrorMessage = "Password do not Match!")]
        public string? ConfirmPassword { get; set; }

    }
}
