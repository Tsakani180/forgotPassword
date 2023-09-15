using System.ComponentModel.DataAnnotations;

namespace ForgotPassword.Models
{
    public class ResetPasswordRequest
    {
        [Required]
        public string Token { get; set; } = string.Empty;
        [Required, MinLength(8, ErrorMessage = "Maximum length i 50 characters"),MaxLength(50, ErrorMessage ="Maximum length i 50 characters")]
        public string Password { get; set; } = string.Empty;
        [Required, Compare("Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

    }
}
