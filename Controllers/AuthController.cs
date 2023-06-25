using FluentValidation;
using Identity1.Models;
using Identity1.Services;
using Identity1.ViewModels;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1.Ocsp;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

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

        /// <summary>
        /// Confirm Email Address
        /// </summary>
        /// <param name="token"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        [HttpGet("[Action]")]
        public async Task<IActionResult> ConfirmEmailLink(string token, string email)
        {
            try
            {
                var result = await _userService.ConfirmEmail(token, email);
                return RedirectPermanent($"https://www.google.com/EmailVerified/{email}");
            }
            catch (Exception ex)
            {
                StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
                throw;
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
            
            var result = await _userService.LoginUserAsync(request);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK, new { message = "User LogedIn!" });
            }
            else if (result.RequiresTwoFactor)
            {
                return StatusCode(StatusCodes.Status200OK,new { RequiresTwoFactor = true, redirectUrl = $"http://localhost:3000/Account/LoginTwoStep?email={request.Email}&rememberMe={request.RememberMe}" });
            }
            else
            {
                return BadRequest(result.IsNotAllowed);
            }
           
        }

        /// <summary>
        /// Enable 2FA For User
        /// </summary>
        /// <returns></returns>
        [HttpPut]
        [Authorize]
        [Route("enable2fa")]
        public async Task<IActionResult> Enable2FA()
        {
            var result = await _userService.Enable2FA();
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK, new { message = "2FA Enabled", user = User.Identity.Name });
            }
            else
            {
                return StatusCode(StatusCodes.Status304NotModified, new { message="Something went wrong!", errors = result.Errors });
            }
        }

        /// <summary>
        /// Cron job From Front End Call When Page LoginTwoStep Rendered
        /// </summary>
        /// <param name="Email"></param>
        /// <param name="RememberMe"></param>
        /// <returns></returns>
        [HttpGet]
        [AllowAnonymous]
        [Route("loginTwoStep")]
        public async Task<IActionResult> LoginTwoStepSendMail([Required]string Email,[DefaultValue(false)]bool RememberMe)
        {
            try
            {
                var result = await _userService.SendTwoStepCode(Email,RememberMe);
                if(result == 200)
                    return Ok(new {Email = Email, RememberMe = RememberMe});
                if (result == StatusCodes.Status400BadRequest)
                    return BadRequest("Not Authenticated!");
                if (result == StatusCodes.Status500InternalServerError) ;
                    return StatusCode(StatusCodes.Status500InternalServerError);
            }
            catch (Exception)
            {
                return StatusCode(StatusCodes.Status500InternalServerError);
                throw;
            }
        }

        /// <summary>
        /// Verify LoginTwoStep Token
        /// </summary>
        /// <param name="modal"></param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        [Route("loginTwoStep")]
        public async Task<IActionResult> LoginTwoStep([FromBody]TwoStepModel modal)
        {
            try
            {
                var result = await _userService.VerifyTwoStepCode(modal);
                if(result.Succeeded)
                    return Ok("User Sign-in Successfully!");
                if (result.IsNotAllowed)
                    return BadRequest("User is Not Allowed!");
                return StatusCode(StatusCodes.Status401Unauthorized);
            }
            catch (Exception)
            {
                return StatusCode(StatusCodes.Status500InternalServerError);
                throw;
            }
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
        /// Forgot Password Send Token
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Forgot Password Request With Token and New Password
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Change Password Request
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword(ChangePassowrdRequest request)
        {
            try
            {
                var result = await _userService.ChangePasswordAsync(request);
                if (result.Succeeded)
                    return Ok("Password Changed Succeesfully!");
                else
                    return BadRequest(result.Errors);
            }
            catch (Exception ex)
            {
                StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
                throw;
            }
        }

        /// <summary>
        /// Get Current User Details
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("me")]
        [Authorize]
        public async Task<IActionResult> getMe()
        {
            try
            {
                var result = await _userService.GetMeAsync();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
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

            if (users.Count > 0)
            {
                return Ok(users);
            }
            else
            {
                return StatusCode(StatusCodes.Status204NoContent, "No Records!");
            }
        }

        /// <summary>
        /// Assign Role To UserEmail
        /// </summary>
        /// <param name="email"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        [HttpPost]
        [Authorize(Roles = "Admin")]
        [Route("addrole/{email}")]
        public async Task<IActionResult> AssignRole([Required] string email, [FromBody][Required] string role)
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
        /// Admin have an access to create new role
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
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
    }
}
