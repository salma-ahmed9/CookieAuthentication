using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System;

namespace AuthenticationWithCookie.Pages;

public class IndexModel : PageModel
{
    [BindProperty]
    public LoginInput LoginInput { get; set; }
    public async Task<IActionResult> OnPost()
   {
        string username = LoginInput.UserName;
        string password = LoginInput.Password;
       if(username==null || password==null) {
          ModelState.AddModelError("", "username and password fields must be entered");
          return Page();
       }
       if(username== "intern" && password== "summer 2023 july")
       {
            var claims = new List<Claim>
            {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, "User"),
            };
            var scheme = CookieAuthenticationDefaults.AuthenticationScheme;
            var claimsIdentity = new ClaimsIdentity(
            claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                AllowRefresh = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),

            };
            var user = new ClaimsPrincipal(claimsIdentity);
            await HttpContext.SignInAsync(scheme, user, authProperties);
            return RedirectToPage("/Index");
        }
       else
       {
            ModelState.AddModelError("", "Invalid username or password");
            return Page();
        }
    }
    public async Task<IActionResult> OnPostLoggingOut()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToPage("/Index");
    }
}
public class LoginInput
{
    public string UserName { get; set; }
    public string Password { get; set; }
}