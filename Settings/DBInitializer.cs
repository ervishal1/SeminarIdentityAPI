using Identity1.Models;
using Microsoft.AspNetCore.Identity;

namespace Identity1.Settings
{
    public class DBInitializer
    {
        public static async Task InitializeAsync(IServiceProvider serviceProvider, UserManager<ApplicationUser> _userManager)
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
            string[] roleNames = { "Admin", "User", "Creator" };
            IdentityResult result;
            foreach (var roleName in roleNames)
            {
                var roleExists = await roleManager.RoleExistsAsync(roleName);
                if (!roleExists)
                {
                    result = await roleManager.CreateAsync(new ApplicationRole() { Name = roleName });
                }
            }

            string Email = "superadmin@gmail.com";
            string Password = "Superadmin@123";

            if (_userManager.FindByEmailAsync(Email).Result == null)
            {
                ApplicationUser user = new ApplicationUser();
                user.UserName = Email;
                user.Email = Email;
                user.EmailConfirmed = true;

                IdentityResult identityResult = _userManager.CreateAsync(user, Password).Result;
                if (identityResult.Succeeded)
                {
                    _userManager.AddToRoleAsync(user, "Admin").Wait();
                }
            }
        }
    }
}
