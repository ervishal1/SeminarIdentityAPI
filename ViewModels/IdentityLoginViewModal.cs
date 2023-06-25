using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Identity1.ViewModels
{
    public class IdentityLoginRequestViewModal
    {

        [Required]
        public string? Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string? Password { get; set; }
        [DefaultValue(false)]
        public bool RememberMe { get; set; } = false;
    }

}
