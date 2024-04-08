using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NuGet.Protocol.Plugins;

namespace AuthRESTfulApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.password, out byte[] passwordHash, out byte[] passwordSalt );
            user.username = request.username;
            user.passwordHash = passwordHash;
            user.passwordSalt = passwordSalt;
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.username != request.username)
            {
                return BadRequest("User not found!");
            }
            if(!VerifyPasswordHash(request.password , user.passwordHash, user.passwordSalt))
            {
                return BadRequest("Password Is incorrect");
            }

            string token = createToken(user);
            return Ok(token);
        }

        private string createToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {new Claim(ClaimTypes.Name , user.username)
            };
            var key = new SymmetricSecurityKey(
                System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken()
                return String.Empty;
        }
        
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password,  byte[] passwordHash,  byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash =  hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }

        }
    }
}
