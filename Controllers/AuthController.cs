using Identity1.Models;
using Identity1.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public readonly IdentityUserServices _userService;

        public AuthController(IdentityUserServices userService)
        {
            _userService = userService;
        }

        [HttpPost]
        [Route("create")]
        public async Task<IActionResult> create(User user)
        {
            IdentityResult result = await _userService.AddUser(user);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK, new { message = "User Created!" });
            }
            else
            {
                return BadRequest();
            }
        }
    }
}
