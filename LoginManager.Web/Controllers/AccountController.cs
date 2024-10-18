using LoginManager.Application.Dto;
using LoginManager.Application.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace LoginManager.Web.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserService _userService;

        public AccountController(UserService userService)
        {
            _userService = userService;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterDto dto)
        {

            try
            {
                if (!ModelState.IsValid)
                    return View(dto);
                await _userService.RegisterUserAsync(dto);

            }
            catch (ArgumentException ex)
            {

                ModelState.AddModelError("", ex.Message);
                return View(dto);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", "An unexpected error occurred. Please try again later.");
                return View(dto);
            }

            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginUserDto dto)
        {
            try
            {
                if (!ModelState.IsValid)
                    return View(dto);
                var user = await _userService.AuthenticateAsync(dto);
                if (user == null)
                {
                    ModelState.AddModelError("", "Invalid credentials.");
                    return View();
                }
                //  cookie or session trail

                var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Email),
                new Claim(ClaimTypes.Role, "User")
            };

                // Create the identity and principal
                var identity = new ClaimsIdentity(claims, "LoginAuth");
                var principal = new ClaimsPrincipal(identity);

                // Sign in with cookie authentication
                await HttpContext.SignInAsync("LoginAuth", principal, new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(30)
                });

            }

            catch (Exception ex)
            {
                ModelState.AddModelError("", "An unexpected error occurred. Please try again later.");
                return View(dto);
            }

            return RedirectToAction("Index", "Home");
        }

    }
}
