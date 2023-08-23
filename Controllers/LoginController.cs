using DemoApi.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DemoApi.Controllers
{
    [Route("api/account")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;
        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        [HttpPost("auth")]
        
        public IActionResult Authen([FromForm] InputUser input)
        {
            User user = new User();
            user.Username = input.Username;
            user.Password = input.Password;
            IActionResult respone = Unauthorized();
            var info = AuthencateUser(user);
            if (info != null)
            {
                var tokenStr = GenerateJSONWebToken(info);
                respone = Ok(new { token = tokenStr });
            }
            return respone;
        }
        private User AuthencateUser(User user)
        {
            User us = null;
            if (user.Username == "admin" && user.Password == "123")
            {
                us = new User
                {
                    Username = "admin",
                    Password = "123",
                    Email = "admin@gmail.com"
                };
            }
            return us;
        }

        private string GenerateJSONWebToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "admin")
            };

            var token = new JwtSecurityToken(
                    issuer: _config["Jwt:Issuer"],
                    audience: _config["Jwt:Issuer"],
                    claims,
                    notBefore: new DateTimeOffset(DateTime.Now).DateTime,
                    expires: new DateTimeOffset(DateTime.Now.AddMinutes(60)).DateTime,
                    signingCredentials: credentials
                );
            //var encodetoken = new JwtSecurityTokenHandler().WriteToken(token);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        [HttpGet("showusername")]
        [Authorize(Roles = "admin")]
        public string showUsername()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            var usernameClaim = identity?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
            var roleClaim = identity?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            if (!string.IsNullOrEmpty(usernameClaim))
            {
                return "Hello " + usernameClaim;
            }

            return "Hello";
        }
    }
}
