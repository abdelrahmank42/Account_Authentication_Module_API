using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Account_Authentication_Module_API.DTO;
using Account_Authentication_Module_API.Model;
using Account_Authentication_Module_API.EmailManagement;
using Account_Authentication_Module_API.EmailManagement.Services;
using System.Net;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Account_Authentication_Module_API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Account_Authentication_Module_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountAuthenticationController : ControllerBase
    {
        private readonly IAccountAuthenticationRepository _accountAuthenticationRepository;
        private readonly IEmailServices _emailServices;
        private readonly IConfiguration _configuration;

        public AccountAuthenticationController(IAccountAuthenticationRepository accountAuthenticationRepository,
            IEmailServices emailServices, IConfiguration configuration)
        {
            // Dependency injection of repository, services, and other required dependencies
            this._accountAuthenticationRepository = accountAuthenticationRepository;
            this._emailServices = emailServices;
            this._configuration = configuration;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDTO registerUserDTO)
        {
            // Check if the input data is valid
            if (ModelState.IsValid)
            {
                // Check if the user already exists
                if (await _accountAuthenticationRepository.FindByEmail(registerUserDTO.Email) == null)
                {
                    // Create a new User object based on the RegisterUserDTO
                    User user = new User() { Email = registerUserDTO.Email, UserName = registerUserDTO.Username };

                    // Create the user and send a confirmation email
                    try
                    {
                        IdentityResult saveResult = await _accountAuthenticationRepository.Create(user, registerUserDTO.Password);
                        if (saveResult.Succeeded)
                        {
                            // Add a role to the user
                            await _accountAuthenticationRepository.AddRole(user, "User");

                            #region confirmation email
                            // Generate an email confirmation token
                            var confirmationToken = await _accountAuthenticationRepository.GenerateEmailConfirmationToken(user);
                            if (!string.IsNullOrEmpty(confirmationToken))
                            {
                                // Create the confirmation link
                                var confirmationLink = Url.Action("ConfirmEmail", "AccountAuthentication", new { token = WebUtility.UrlEncode(confirmationToken), email = user.Email }, Request.Scheme);

                                // Create the email message
                                var confirmationMessage = new Message(new string[] { user.Email }, "Confirmation Email", $"Hi, {user.UserName}.\n\nYour confirmation link:\n{confirmationLink}");

                                // Send the email
                                _emailServices.SendEmail(confirmationMessage, _configuration["AccountName"]);

                                return Ok($"Email sent to {user.Email}");
                            }
                            else
                                ModelState.AddModelError("", "No confirmation token!");
                            #endregion
                        }
                        else
                            foreach (var error in saveResult.Errors)
                                ModelState.AddModelError("", error.Description);
                    }
                    catch (Exception ex)
                    {
                        ModelState.AddModelError("", ex.Message);
                    }
                }
                else
                    ModelState.AddModelError("", "Email already exists!");
            }
            return BadRequest(ModelState);
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            // Check if the user exists
            var user = await _accountAuthenticationRepository.FindByEmail(email);
            if (user != null)
            {
                // Confirm the email with the provided token
                var result = await _accountAuthenticationRepository.ConfirmEmail(user, WebUtility.UrlDecode(token));
                if (result.Succeeded)
                    // Email confirmed successfully
                    return Ok("Email Confirmed :)");

                // Error occurred during email confirmation
                return BadRequest(result.Errors);
            }
            // User not found
            return NotFound();
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginUserDTO loginUserDTO)
        {
            // Check if the user exists and the password is correct
            User user = await _accountAuthenticationRepository.FindByEmail(loginUserDTO.Email);
            if (user != null && await _accountAuthenticationRepository.CheckPassword(user, loginUserDTO.Password))
            {
                #region Claims Creation
                // Create claims for the user
                List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
                // Add roles to the claims
                foreach (var role in await _accountAuthenticationRepository.GetRoles(user))
                    claims.Add(new Claim(ClaimTypes.Role, role.ToString()));
                #endregion

                // Generate a login token
                JwtSecurityToken loginToken = _accountAuthenticationRepository.GenerateToken(claims);
                // Return the token
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(loginToken),
                    expiration = loginToken.ValidTo
                });
            }
            return Unauthorized();
        }

        [HttpPost("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            // Find the user by email
            User user = await _accountAuthenticationRepository.FindByEmail(email);
            if (user != null)
            {
                #region reset password email 
                // Generate a password reset token
                var resetPasswordToken = await _accountAuthenticationRepository.GeneratePasswordResetToken(user);
                if (!string.IsNullOrEmpty(resetPasswordToken))
                {
                    // Create the reset password link
                    var resetPasswrdLink = Url.Action("ResetPassword", "AccountAuthentication", new { token = resetPasswordToken, email = user.Email }, Request.Scheme);
                    // Create the email message
                    var resetpasswordMessage = new Message(new string[] { user.Email }, "Reset Password", $"Hi, {user.UserName}.\n\nYour reset password link:\n{resetPasswrdLink}");
                    // Send the email
                    _emailServices.SendEmail(resetpasswordMessage, _configuration["AccountName"]);
                    return Ok($"Email sent to {user.Email}");
                }
                else
                    ModelState.AddModelError("", "No reset password token!");
                #endregion
            }
            return NotFound();
        }

        [HttpGet("ResetPassword")]
        public IActionResult ResetPassword(string email, string token) => Ok(new ResetPasswordDTO { Email = email, Token = token });

        [HttpPost("ResetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDTO resetPasswordDTO)
        {
            // Find the user by email
            User user = await _accountAuthenticationRepository.FindByEmail(resetPasswordDTO.Email);
            if (user != null)
            {
                // Reset the password using the provided token
                IdentityResult resetPassResult = await _accountAuthenticationRepository.ResetPassword(user, resetPasswordDTO.Token, resetPasswordDTO.Password);
                if (resetPassResult.Succeeded)
                    return Ok($"Password has been changed!");
                else
                {
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return BadRequest(ModelState);
                }
            }
            return NotFound();
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles ="Admin")]
        [HttpPost("PormoteUser")]
        public async Task<IActionResult> PromoteUser(string email)
        {
            User user = await _accountAuthenticationRepository.FindByEmail(email);
            if (user != null)
            {
                await _accountAuthenticationRepository.AddRole(user, "Admin");
                var confirmationMessage = new Message(new string[] { user.Email }, "Confirmation Email", $"Hi, {user.UserName}.\n\nYou're now admin!");
                _emailServices.SendEmail(confirmationMessage, _configuration["AccountName"]);

                return Ok("User Promoted :)");
            }
            return NotFound();
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
        [HttpPost("RemoveAdmin")]
        public async Task<IActionResult> RemoveAdmin(string email)
        {
            User user = await _accountAuthenticationRepository.FindByEmail(email);
            if (user != null)
            {
                await _accountAuthenticationRepository.RemoveRole(user, "Admin");
                var confirmationMessage = new Message(new string[] { user.Email }, "Confirmation Email", $"Hi, {user.UserName}.\n\nYou're no longer admin now!");
                _emailServices.SendEmail(confirmationMessage, _configuration["AccountName"]);

                return Ok("Admin Removed!");
            }
            return NotFound();
        }
    }
}
