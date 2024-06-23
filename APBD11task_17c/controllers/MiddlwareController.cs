using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace APBD11_17c.controllers;
[Route("api/[controller]")]
[ApiController]
public class MiddlwareController: ControllerBase
{
    private readonly IConfiguration _configuration;

    public MiddlwareController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult RegisterStudent(string password)
    {
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            new byte[] {0},
            10,
            HashAlgorithmName.SHA512, 
            128
            );

        return Ok(Convert.ToHexString(hash));
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public IActionResult Login(LoginRequestModel loginRequest)
    {
        if(!(loginRequest.UserName.ToLower() == "test" && loginRequest.Password == "test"))
        {
            return Unauthorized("Wrong username or password");
        }

        Claim[] userclaim = new[]
        {
            new Claim(ClaimTypes.Name, "user"),
            new Claim(ClaimTypes.Role, "mkdir"),
            new Claim(ClaimTypes.Role, "admin")
        };

        SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecretKey"]));

        SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        JwtSecurityToken token = new JwtSecurityToken(
            issuer: "https://localhost:5001",
            audience: "https://localhost:5001",
            claims: userclaim,
            expires: DateTime.Now.AddMinutes(10),
            signingCredentials: creds
        );

        var RefreshTokenExp = DateTime.Now.AddDays(1);

        return Ok(new
        {
            accessToken = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshTokenExp
        });
    }
    
    [HttpPost("verify-password")]
    public IActionResult VerifyPassword(VerifyPasswordRequestModel requestModel)
    {
        var passwordHasher = new PasswordHasher<User>();
        return Ok(passwordHasher.VerifyHashedPassword(new User(), requestModel.Hash, requestModel.Password) == PasswordVerificationResult.Success);
    }

    [Authorize(AuthenticationSchemes = "IgnoreTokenExpirationScheme")]
    [HttpPost("refresh")]
    public IActionResult Refresh(RefreshTokenRequestModel refreshToken)
    {
        var user = new User { Name = "mkdir" };
        if (user == null)
        {
            throw new SecurityTokenException("Invalid refresh token");
        }
        
        Claim[] userclaim = new[]
        {
            new Claim(ClaimTypes.Name, "mkdir"),
            new Claim(ClaimTypes.Role, "user"),
            new Claim(ClaimTypes.Role, "admin")
        };

        SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecretKey"]));

        SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        JwtSecurityToken jwtToken = new JwtSecurityToken(
            issuer: "https://localhost:5001",
            audience: "https://localhost:5001",
            claims: userclaim,
            expires: DateTime.Now.AddMinutes(10),
            signingCredentials: creds
        );
       
        return Ok(new
        {
            accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken),
        });
    }

}

public class VerifyPasswordRequestModel
{
    public string Password { get; set; } = null!;
    public string Hash { get; set; } = null!;
}
    
public class User
{
    public string Name { get; set; } = null!;
    public string Password { get; set; } = null!;
}

public class RefreshTokenRequestModel
{
        public string RefreshToken { get; set; } = null!;
}

public class LoginResponseModel
{
    public string Token { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
}

public class LoginRequestModel
{
    [Required]
    public string UserName { get; set; } = null!;
    [Required]
    public string Password { get; set; } = null!;
}