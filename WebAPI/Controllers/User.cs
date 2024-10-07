using Application.Contracts;
using Application.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class User : ControllerBase
    {
        private readonly IUser user;

        public User(IUser user)
        {
            this.user = user;
        }

        [HttpPost("login")]
        public async Task<ActionResult<LoginResponse>> LoginUserIn(LoginDTO loginDTO)
        {
            var result = await user.LoginUserAsync(loginDTO);
            return Ok(result);
        }
        [HttpPost("register")]
        public async Task<ActionResult<LoginResponse>> RegisterUser(RegisterUserDTO registerUserDTO)
        {
            var result = await user.RegisterUserAsync(registerUserDTO);
            return Ok(result);
        }
    }
}
