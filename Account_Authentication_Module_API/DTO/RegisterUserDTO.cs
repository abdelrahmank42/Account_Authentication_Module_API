using System.ComponentModel.DataAnnotations;

namespace Account_Authentication_Module_API.DTO
{
    public class RegisterUserDTO
    {
        [Required]
        public string Username { get; set; } 

        [Required, DataType(DataType.EmailAddress)]
        public string Email { get; set; } 

        [Required, DataType(DataType.Password)]
        public string Password { get; set; } 
        [Compare("Password"), DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } 
    }
}
