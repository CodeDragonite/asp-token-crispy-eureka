using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TokenAuthAPI.Data;
using TokenAuthAPI.Data.Helpers;
using TokenAuthAPI.Data.Models;
using TokenAuthAPI.Data.ViewModels;

namespace TokenAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser>? _userManager;
        private readonly RoleManager<IdentityRole>? _roleManager;
        private readonly AppDbContext? _appDbContext;
        private readonly ILogger<AuthenticationController>? _logger;
        private readonly IConfiguration? _configuration;
        private readonly TokenValidationParameters? _tokenValidationParams;

        public AuthenticationController(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            AppDbContext appDbContext,
            IConfiguration configuration,
            TokenValidationParameters? tokenValidationParams)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _appDbContext = appDbContext;
            _configuration = configuration;
            _tokenValidationParams = tokenValidationParams; 
        }

        [HttpPost("register-user")]
        public async Task<IActionResult> Register([FromBody] RegisterVM registerVM)
        {
            if (!ModelState.IsValid)
                return BadRequest("Please, provide the required fields");

            ApplicationUser userExists = await _userManager.FindByEmailAsync(registerVM.Email);
            if (userExists != null) return BadRequest($"User {registerVM.Email} already exists");

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerVM.FirstName,
                LastName = registerVM.LastName,
                Email = registerVM.Email,
                UserName = registerVM.Username,
                Custom = "Weiasdasd",
                SecurityStamp = Guid.NewGuid().ToString()

            };
            var results = await _userManager.CreateAsync(newUser, registerVM.Password);
            if (results.Succeeded)
            {
                switch(registerVM.Role)
                {
                    case UserRoles.Manager:
                        await _userManager.AddToRoleAsync(newUser, UserRoles.Manager);
                        break;
                    case UserRoles.Student:
                        await _userManager.AddToRoleAsync(newUser, UserRoles.Student);
                        break;
                    default:
                        break;
                }
                return Ok("user created");
            }
            return BadRequest("User could not be created");
        }

        [HttpPost("login-user")]
        public async Task<IActionResult> Login([FromBody] LoginVM loginVM)
        {
            if (!ModelState.IsValid)
                return BadRequest("Please, provide all required fields");

            ApplicationUser userExists = await _userManager.FindByEmailAsync(loginVM.Email);
            if (userExists != null && await _userManager.CheckPasswordAsync(userExists, loginVM.Password))
            {
                var tokenValue = await GenerateJWTToken(userExists, null);


                return Ok(tokenValue);
            }
            return Unauthorized();
        }


        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequestVM tokenRequestVM)
        {
            if (!ModelState.IsValid)
                return BadRequest("Please, provide all required fields");
            var result = await VerifyAndGenerateTokenAsync(tokenRequestVM);
            return Unauthorized();

        }

        private async Task<AuthResultVM> VerifyAndGenerateTokenAsync(TokenRequestVM tokenRequestVM)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var storedToke = await _appDbContext.RefreshToken.FirstOrDefaultAsync(x => x.Token == tokenRequestVM.Token);
            var dbUser = await _userManager.FindByIdAsync(storedToke.UserId);
            try
            {
                var tokenCheckResult = jwtTokenHandler.ValidateToken(tokenRequestVM.Token,
                    _tokenValidationParams, out var validatedToken);
                return await GenerateJWTToken(dbUser, storedToke);
            }
            catch (SecurityTokenExpiredException stee)
            {

                if(storedToke.DateExpire >= DateTime.UtcNow)
                {
                    return await GenerateJWTToken(dbUser, storedToke);
                }
                else
                {
                    return await GenerateJWTToken(dbUser, null);
                }
            }
            
        }

        private async Task<AuthResultVM> GenerateJWTToken(ApplicationUser user, RefreshToken reToken)
        {
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Email, user.Email),
                new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            //Add User Roles Claims
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach(var urole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, urole));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                expires: DateTime.UtcNow.AddMinutes(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            if(reToken != null)
            {

                var rTokenresponse = new AuthResultVM()
                {
                    Token = jwtToken,
                    RefreshToken = reToken.Token,
                    ExpiresAt = token.ValidTo
                };
                return rTokenresponse;
            }

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsRevoked = false,
                UserId = user.Id,
                DateAdded = DateTime.UtcNow,
                DateExpire = DateTime.UtcNow.AddMonths(6),
                Token = Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString()
            };

            await _appDbContext.RefreshToken.AddRangeAsync(refreshToken);
            await _appDbContext.SaveChangesAsync();

            var response = new AuthResultVM()
            {
                Token = jwtToken,
                RefreshToken = refreshToken.Token,
                ExpiresAt = token.ValidTo
            };

            return response;
        }
    }
}
