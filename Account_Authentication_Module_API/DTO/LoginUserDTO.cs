using System.ComponentModel.DataAnnotations;

namespace Account_Authentication_Module_API.DTO
{
    public class LoginUserDTO
    {
        [Required, DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required, DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
