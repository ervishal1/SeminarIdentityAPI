using AspNetCore.Identity.MongoDbCore.Models;
using Identity1.Models;
using Identity1.Settings;
using Identity1.Settings.MailSetting;
using Identity1.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Org.BouncyCastle.Asn1.Ocsp;
using System;
using System.Data;
using System.Security.Policy;
using System.Text;
using System.Text.Encodings.Web;

namespace Identity1.Services
{
    public class IdentityUserServices
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IMailService _mailService;
        public IdentityUserServices(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IMailService mailService
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _mailService = mailService;
        }

        public async Task<IdentityResult> AddUser(User user)
        {
            ApplicationUser appUser = new ApplicationUser
            {
                UserName = user.Name,
                Email = user.Email
            };

            IdentityResult result = await _userManager.CreateAsync(appUser, user.Password);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            var confirmationlink = "https://localhost:7022/api/auth/ConfirmEmailLink?token=" + code + "&email=" + appUser.Email;
            string template = GetConfirmEmailTemplate();
            var message = new MailRequest();
            message.ToEmail = appUser.Email;
            message.Subject = "Confirm your email";
            message.Body = template.Replace("{0}", HtmlEncoder.Default.Encode(confirmationlink));


            await _mailService.SendEmailAsync(message);
            if (result.Succeeded) {
                _userManager.AddToRoleAsync(appUser, "User").Wait();
            }
            return result;
        }

        private string GetConfirmEmailTemplate()
        {
            string line = string.Empty;
            FileStream fileStream = new FileStream(Path.Combine("template", "EmailConfirmation.txt"), FileMode.Open);
            using (StreamReader reader = new StreamReader(fileStream))
            {
                line = reader.ReadToEnd();
            }

            return line;
        }

        public async Task<IdentityResult> ConfirmEmail(string token, string email)
        {
            ApplicationUser user = await _userManager.FindByEmailAsync(email);
            if(user != null)
            {
                token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
                return await _userManager.ConfirmEmailAsync(user, token);
            }
            else
            {
                return IdentityResult.Failed();
            }
        }

        public async Task<IdentityResult> CreateRole(string name)
        {
            var obj = await _roleManager.FindByNameAsync(name);
            if(obj == null)
            {
                return await _roleManager.CreateAsync(new ApplicationRole() { Name = name });
            }
            else
            {
                return IdentityResult.Failed();
            }
        }

        public async Task<SignInResult> LoginUserAsync(IdentityLoginRequestViewModal request)
        {
            ApplicationUser user = await _userManager.FindByEmailAsync(request.Email);
            bool isNotEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user); 
            if(user != null && isNotEmailConfirmed)
            {
                SignInResult result = await _signInManager.PasswordSignInAsync(user, request.Password,true,false);
                return result;
            }
            return SignInResult.Failed;

        }

        public async Task LogoutAsync()
        {
            await _signInManager.SignOutAsync();
        }

        public async Task<List<ApplicationUserResponse>> GetUsersByRole(string role)
        {
            IList<ApplicationUser> users = await _userManager.GetUsersInRoleAsync(role);
            return await GetAllUsersJSON(users);
        }

        public async Task<List<ApplicationUserResponse>> GetAllUsers()
        {
            IList<ApplicationUser> users = _userManager.Users.ToList();
            return await GetAllUsersJSON(users);
        }

        public async Task<List<ApplicationUserResponse>> GetAllUsersJSON(IList<ApplicationUser> usersList)
        {
            List<ApplicationUserResponse> response = new List<ApplicationUserResponse>();
            List<ApplicationUser> users = usersList.ToList();
            foreach (var user in users)
            {
                ApplicationUserResponse res = new ApplicationUserResponse()
                {
                    Id = user.Id.ToString(),
                    UserName = user.UserName,
                    Email = user.Email,
                    ProfileImg = user.ProfileImg,
                    EmailConfirmed = user.EmailConfirmed,
                    Roles = await GetUserRolesByEmail(user.Email),
                    CreatetAt = user.CreatedOn,       
                };
                response.Add(res);
            }

            return response;
        }

        public async Task<IdentityResult> AssignRoleToUser(string userEmail,string role)
        {
            ApplicationUser user = await _userManager.FindByEmailAsync(userEmail);  
            return await _userManager.AddToRoleAsync(user,role);
        }

        public async Task<IdentityResult> RemoveRoleOfUser(string userEmail,string role)
        {
            ApplicationUser user = await _userManager.FindByEmailAsync(userEmail);
            return await _userManager.RemoveFromRoleAsync(user, role);
        }

        public async Task<IList<string>> GetUserRolesByEmail(string userEmail)
        {
            ApplicationUser user = await _userManager.FindByEmailAsync(userEmail);
            return await _userManager.GetRolesAsync(user);
        }

        public  IList<string> GetAllRoles()
        {
            return _roleManager.Roles.Select(x=> x.Name).ToList();
        }
    }
}
