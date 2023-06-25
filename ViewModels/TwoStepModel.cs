using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Identity1.ViewModels
{
    public class TwoStepModel
    {
        [Required]
        [DataType(DataType.Text)]
        public string TwoFactorCode { get; set; }
        [DefaultValue(false)]
        public bool RememberMe { get; set; }
    }
}
