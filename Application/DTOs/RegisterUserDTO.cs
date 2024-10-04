using System.ComponentModel.DataAnnotations;

namespace Application.DTOs
{
    public class RegisterUserDTO
    {
        [Required]
        public string? FirstName { get; set; } = string.Empty;
        [Required]
        public string? LastName { get; set; } = string.Empty;
        [Required, EmailAddress]
        public string? Email { get; set; } = string.Empty;
        [Required]
        public string? Password { get; set; } = string.Empty;
        [Required, Compare(nameof(Password))]
        public string? ConfirmPassword { get; set; } = string.Empty;

    }
}
