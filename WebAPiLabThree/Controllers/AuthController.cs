using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebAPiLabThree.Data.Models;
using WebAPiLabThree.DTOs;
using WebAPiLabThree.JWT;

namespace WebAPiLabThree.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<Employee> _usermanager;
        private readonly IConfiguration _config;
        public AuthController(UserManager<Employee> usermanager, IConfiguration config)
        {
            _usermanager = usermanager;
            _config = config;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<ActionResult> Register(RegisterDto model)
        {
            //creating new user object
            Employee emp = new Employee
            {
                UserName = model.UserName,
                Department = model.Department
            };
            //create new user using user manager
            var newEmp = await _usermanager.CreateAsync(emp, model.Password);
            //Check user credentials
            if(!newEmp.Succeeded)
            {
                return BadRequest(newEmp.Errors);
            }
            //Adding claim to user
            var myClaims = new List<Claim> {
                //Must add this claim in order to access the user global property after that in another controllers
                new Claim(ClaimTypes.NameIdentifier, emp.Id),
                new Claim(ClaimTypes.Role,"CEO")
            };
            //Adding those claims to user
            var result = await _usermanager.AddClaimsAsync(emp, myClaims);
            //Generate the token
            var secretKey = _config.GetValue<string>("SecretKey");
            var KeyInBytes = Encoding.ASCII.GetBytes(secretKey);
            var key = new SymmetricSecurityKey(KeyInBytes);
            var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var jwtToken = new JwtSecurityToken(
                    claims:myClaims,
                    signingCredentials:signingCredentials,
                    //signingCredentials:JWT.JWT.signingCredentials,
                    expires:DateTime.Now.AddMinutes(15)
                );
            //In order to use the token as string
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.WriteToken(jwtToken);
            return Ok(new
            {
                token=token,
                ExpiresAfter= 15
            });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult> Login(LoginDto model)
        {
            //Getting the user by his username
            var user = await _usermanager.FindByNameAsync(model.UserName);
            //getting user claims to check its authorizing
            var myClaims = await _usermanager.GetClaimsAsync(user);
            //Check on the pasword
            if(!await _usermanager.CheckPasswordAsync(user,model.Password))
            {
                return Unauthorized();
            }
            //var secretKey = _config.GetValue<string>("SecretKey");
            //var KeyInBytes = Encoding.ASCII.GetBytes(secretKey);
            //var key = new SymmetricSecurityKey(KeyInBytes);
            //var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            JWT.JWT myJwt = new JWT.JWT(_config);
            var signingCredentials = myJwt.getCredentials();

            var jwtToken = new JwtSecurityToken(
                    claims: myClaims,
                    signingCredentials: signingCredentials,
                    //signingCredentials:JWT.JWT.signingCredentials,
                    expires: DateTime.Now.AddMinutes(15)
                );
            //In order to use the token as string
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.WriteToken(jwtToken);
            return Ok(new
            {
                token = token,
                ExpiresAfter = 15
            });
        }

        [HttpGet]
        [Route("Authorization")]
        [Authorize]
        public ActionResult CheckAuthority()
        {
            return Ok();
        }

        [HttpGet]
        [Route("Authentication")]
        [Authorize(policy:"CEO")]
        public ActionResult checkAuthorization()
        {
            return Ok("Welcome CEO");
        }

        
    }
}
