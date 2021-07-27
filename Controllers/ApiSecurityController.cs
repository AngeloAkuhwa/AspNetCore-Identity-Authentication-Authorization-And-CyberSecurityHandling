using IdentityNetCore.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ApiSecurityController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public ApiSecurityController(
            IConfiguration configuration,
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager)
        {
            _configuration = configuration;
            _signInManager = signInManager;
            _userManager = userManager;
        }
        public async Task<IActionResult> TokenAuth(SignInViewModel model)
        {
            var issuer = _configuration["Tokens:Issuer"];
            var audience = _configuration["Tokens:Audience"];
            var key = _configuration["Tokens:Key"];

            if (ModelState.IsValid)
            {
                var sigInResult = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, false, false);
                if (sigInResult.Succeeded)
                {
                    var user = await _userManager.FindByEmailAsync(model.UserName);
                    if(user != null)
                    {
                        var claims = new[]
                        {
                            new Claim(JwtRegisteredClaimNames.Email, user.Email),
                            new Claim(JwtRegisteredClaimNames.Jti, user.Id)
                        };
                        var ketToBytes = Encoding.UTF8.GetBytes(key);
                        var securityKey = new SymmetricSecurityKey(ketToBytes);
                        var credentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);
                        var token = new JwtSecurityToken(
                            issuer,audience,claims,
                            expires: DateTime.Now.AddMinutes(30),
                            signingCredentials: credentials);

                        return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token) });
                       
                    }
                }
            }
            return Ok();
        }
    }
}
