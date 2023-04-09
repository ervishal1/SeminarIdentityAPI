using FluentValidation;
using Identity1.Models;
using Identity1.Services;
using Identity1.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.ComponentModel.DataAnnotations;

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

        /// <summary>
        /// User Regsiter
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("create")]
        public async Task<IActionResult> Create([FromBody] User user)
        {
            IdentityResult result = await _userService.AddUser(user);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status201Created, new { message = "Signup Successfully, Please Confirm your Email!" });
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }

        [HttpPost]
        [Route("createrole")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateRole([FromForm][Required] string name)
        {
            if (String.IsNullOrEmpty(name))
                return BadRequest();

            IdentityResult result = await _userService.CreateRole(name);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status201Created, new { message = "Role Created!" });
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }

        /// <summary>
        /// Login User 
        /// </summary>
        /// <param name="request"></param>
        /// <param name="validate"></param>
        /// <returns></returns>

        [HttpPost]
        [AllowAnonymous]
        [Route("login")]
        public async Task<IActionResult> Login([FromForm]IdentityLoginRequestViewModal request)
        {
            //var valid = await validate.ValidateAsync(request);
            //if (valid.IsValid)
            //{
                var result = await _userService.LoginUserAsync(request);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new { message = "User LogedIn!" });
                }
                else
                {
                    return BadRequest(result.IsNotAllowed);
                }
            //}
            //else
            //{
            //    return BadRequest(valid.Errors);
            //}
        }

        /// <summary>
        /// User Signout
        /// </summary>
        /// <returns></returns>

        [HttpPost]
        [Authorize]
        [Route("logout")]
        public async Task<IActionResult> Logout()
        {
            await _userService.LogoutAsync();
            return StatusCode(StatusCodes.Status200OK, new { message = "User SignOut" } );
        }

        /// <summary>
        /// Get Users By Its Roles
        /// </summary>
        /// <param name="roleType"></param>
        /// <returns></returns>
       
        [HttpGet]
        [Authorize(Roles = "Admin")]
        [Route("users")]
        public async Task<IActionResult> GetUsers(string? roleType)
        {
            List<ApplicationUserResponse> users = new();
            if (!String.IsNullOrEmpty(roleType))
            {
               users = await _userService.GetUsersByRole(roleType);
            }
            else
            {
                users = await _userService.GetAllUsers();  
            }

            if(users.Count > 0)
            {
                return Ok(users);
            }
            else
            {
                return StatusCode(StatusCodes.Status204NoContent, "No Records!");
            }
        }

        /// <summary>
        /// Assign Role TO UserEmail
        /// </summary>
        /// <param name="email"></param>
        /// <param name="role"></param>
        /// <returns></returns>

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [Route("addrole/{email}")]
        public async Task<IActionResult> AssignRole([Required] string email,[FromBody] [Required] string role)
        {
            try
            {
                IdentityResult result = await _userService.AssignRoleToUser(email, role);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new { message = "Role Assigned!" });
                }
                else
                {
                    return BadRequest(result.Errors);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        /// <summary>
        /// Confirm Email Address
        /// </summary>
        /// <param name="token"></param>
        /// <param name="email"></param>
        /// <returns></returns>
       
        [HttpGet("[Action]")]
        //[Route("ConfirmEmailLink{token}{email}")]
        public async Task<IActionResult> ConfirmEmailLink(string token, string email)
        {
            try
            {
                var result = await _userService.ConfirmEmail(token, email);
                return RedirectPermanent($"https://www.google.com/EmailVerified/{email}");
            }
            catch (Exception ex)
            {
                StatusCode(StatusCodes.Status500InternalServerError,ex.Message);
                throw;
            }
  
        }

        [HttpPost]
        [Route("user/reset-password")]
        public async Task<IActionResult> ResetPassword(string email)
        {
            try
            {
                var result = await _userService.ResetPassowrdTokenGen(email);
                if (result)
                    return Ok("Reset Email Send!");
                else
                    return BadRequest("Oops Something Wrong!");
            }
            catch (Exception ex)
            {
                StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
                throw;
            }
        }

        [HttpPost]
        [Route("user/reset-password-confirm")]
        public async Task<IActionResult> ResetPasswordConfirmToken(ResetPasswordRequest request)
        {
            try
            {
                var result = await _userService.ResetPassowrdConfirm(request);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new { message = "Password Reset Successfully!" });
                }
                else
                {
                    return BadRequest(result.Errors);
                }
            }
            catch (Exception ex)
            {
                StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
                throw;
            }
        }
    }
}
