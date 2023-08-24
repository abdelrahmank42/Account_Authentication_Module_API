using Account_Authentication_Module_API.Model;
using Account_Authentication_Module_API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Account_Authentication_Module_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class TestController : ControllerBase
    {
        private readonly IAccountAuthenticationRepository _accountAuthenticationRepository;

        public TestController(IAccountAuthenticationRepository accountAuthenticationRepository) => _accountAuthenticationRepository = accountAuthenticationRepository;


        [HttpGet("GetAll"), Authorize(Roles = "Admin")]
        public List<User> GetAllAccounts() => _accountAuthenticationRepository.GetAll();
    }
}
