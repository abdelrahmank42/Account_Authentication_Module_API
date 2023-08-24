using Account_Authentication_Module_API.Model;
using Microsoft.AspNetCore.Identity;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Account_Authentication_Module_API.Services
{
    public interface IAccountAuthenticationRepository
    {
        Task<User> FindByEmail(string email);
        Task<IEnumerable> GetRoles(User user);
        JwtSecurityToken GenerateToken(List<Claim> claims);
        Task<string> GeneratePasswordResetToken(User user);
        Task<bool> CheckPassword(User user, string password);
        Task<IdentityResult> AddRole(User user, string role);
        Task<string> GenerateEmailConfirmationToken(User user);
        Task<IdentityResult> Create(User user, string password);
        Task<IdentityResult> RemoveRole(User user, string role);
        Task<IdentityResult> ConfirmEmail(User user, string token);
        Task<IdentityResult> ResetPassword(User user, string token, string password);

        List<User> GetAll();
        Task<User> GetProfile(string email);
    }
}