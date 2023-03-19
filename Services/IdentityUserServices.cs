using Identity1.Models;
using Microsoft.AspNetCore.Identity;

namespace Identity1.Services
{
    public class IdentityUserServices
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public IdentityUserServices(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<IdentityResult> AddUser(User user)
        {
            ApplicationUser appUser = new ApplicationUser
            {
                UserName = user.Name,
                Email = user.Email
            };

            IdentityResult result = await _userManager.CreateAsync(appUser, user.Password);

            return result;
        }
    }
}
