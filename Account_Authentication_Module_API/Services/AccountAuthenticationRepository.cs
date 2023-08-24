using Account_Authentication_Module_API.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Account_Authentication_Module_API.Services
{
    public class AccountAuthenticationRepository : IAccountAuthenticationRepository
    {
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _configuration;

        public AccountAuthenticationRepository(UserManager<User> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }
        public JwtSecurityToken GenerateToken(List<Claim> claims)
        {
            //create SigningCredentials with security key
            SecurityKey securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));

            //create token.
            return new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    claims: claims,
                    expires: DateTime.Now.AddHours(1),
                    signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
                );
        }
        public async Task<IEnumerable> GetRoles(User user) => await _userManager.GetRolesAsync(user);
        public async Task<User> FindByEmail(string email) => await _userManager.FindByEmailAsync(email);
        public async Task<IdentityResult> AddRole(User user, string role) => await _userManager.AddToRoleAsync(user, role);
        public async Task<IdentityResult> Create(User user, string password) => await _userManager.CreateAsync(user, password);
        public async Task<IdentityResult> RemoveRole(User user, string role) => await _userManager.RemoveFromRoleAsync(user, role);
        public async Task<bool> CheckPassword(User user, string password) => await _userManager.CheckPasswordAsync(user, password);
        public async Task<string> GeneratePasswordResetToken(User user) => await _userManager.GeneratePasswordResetTokenAsync(user);
        public async Task<IdentityResult> ConfirmEmail(User user, string token) => await _userManager.ConfirmEmailAsync(user, token);
        public async Task<string> GenerateEmailConfirmationToken(User user) => await _userManager.GenerateEmailConfirmationTokenAsync(user);
        public async Task<IdentityResult> ResetPassword(User user, string token, string password) => await _userManager.ResetPasswordAsync(user, token, password);


        public List<User> GetAll() => _userManager.Users.ToList();
        public async Task<User> GetProfile(string email) => await _userManager.FindByEmailAsync(email);
    }
}
