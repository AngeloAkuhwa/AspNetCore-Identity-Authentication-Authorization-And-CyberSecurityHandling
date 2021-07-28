using IdentityNetCore.Models;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        private SignInManager<IdentityUser> _signInManager { get; }
        private IEmailSender _emailSender { get; }

        public IdentityController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IEmailSender emailSender)
        {
            this.userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailSender = emailSender;
        }

        public IActionResult SignUp()
        {
            SignUpViewModel model = new SignUpViewModel { Role = "Member"};

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignUpViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (!await _roleManager.RoleExistsAsync(model.Role))
                {
                    var role = new IdentityRole { Name = model.Role };
                    var roleResult = await _roleManager.CreateAsync(role);
                    if (!roleResult.Succeeded)
                    {
                        var errors = roleResult.Errors.Select(x => x.Description);

                        ModelState.AddModelError("role", string.Join(", ", errors));

                        return View(model);
                    }
                }


                if(await userManager.FindByEmailAsync(model.Email) == null)
                {
                    IdentityUser user = new IdentityUser
                    {
                        Email = model.Email,
                        UserName = model.Email
                    };

                   IdentityResult result = await userManager.CreateAsync(user, model.PassWord);

                    if (result.Succeeded)
                    {
                        //fetch registerd user
                        var registeredUser = await userManager.FindByEmailAsync(user.Email);

                        //adds role to registered user

                        await userManager.AddToRoleAsync(registeredUser, model.Role);

                        //generates user claim

                        var claim = new Claim("Department", model.Department);

                        //adds claim to a registered user

                        await userManager.AddClaimAsync(registeredUser, claim);

                        //generate confirmation token
                        var token = await userManager.GenerateEmailConfirmationTokenAsync(registeredUser);

                        //generates confirmation link

                        var confirmEmailLink = Url.Action("ConfirmEmail", "Identity", new { userId = registeredUser.Id, @token = token });

                       await _emailSender.SendEmailAsync("info@mydomain.com", registeredUser.Email, "ConfirmEmail", confirmEmailLink);

                        return RedirectToAction("SignIn");
                    }

                    ModelState.AddModelError("SignUp", string.Join(", ", result.Errors.Select(x => x.Description)));

                    return View(model);
                }

                return View("user already exist");
            }
            return View(model);
        }

       
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> MultiFactorAuthenticationSetUp()
        {
            const string provider = "asp.netIdentity";
            var loggedInUser = await userManager.GetUserAsync(User);

            await userManager.ResetAuthenticatorKeyAsync(loggedInUser);

            var token = await userManager.GetAuthenticatorKeyAsync(loggedInUser);

            var qrCodeUrl = $"otpauth://totp/{provider}:{loggedInUser.Email}?secret={token}&issuer={provider}&digits=6";

            MultiFactorAuthViewModel multiFactorAuth = new MultiFactorAuthViewModel { Token = token,QRCodeUrl =qrCodeUrl};

            return View(multiFactorAuth);
        }

        
        [HttpPost]
        [Authorize]
        public async Task<IActionResult> MultiFactorAuthenticationSetUp(MultiFactorAuthViewModel model)
        {
            var loggedInUser = await userManager.GetUserAsync(User);

           var succeeded = await userManager.VerifyTwoFactorTokenAsync(loggedInUser, userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
            if (succeeded)
            {
                await userManager.SetTwoFactorEnabledAsync(loggedInUser,true);
                return View("SuccessAuth");
            }
            else
            {
                ModelState.AddModelError("Verify","Your MFA code could not be validated");
            }


            return View(model);
        }

        [HttpGet]
        public IActionResult SuccessAuth()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ConfirmEmail(string userId,string token)
        {
            var user = await userManager.FindByIdAsync(userId);

            var confirmEmail = await userManager.ConfirmEmailAsync(user, token);

            if(confirmEmail.Succeeded)
            {
                return RedirectToAction("SignIn");
            }

            return new NotFoundResult();
        }

        public IActionResult SignIn()
        {
            return View(new SignInViewModel());
        }
        [HttpPost]
        public async Task<IActionResult> SignIn(SignInViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, false);
                
                var user1 = HttpContext.User;
                if (result.Succeeded)
                {
                  

                    var user = await userManager.FindByEmailAsync(model.UserName);

                    var userClaims = await userManager.GetClaimsAsync(user);
                    var isInAdminRole = await userManager.IsInRoleAsync(user, "Admin");
                    var isInUserRole = await userManager.IsInRoleAsync(user, "Member");

                    if (!userClaims.Any(x => x.Type == "Department"))
                    {
                        ModelState.AddModelError("Department", "user does not have a department");
                        return View(model);
                    }

                    if(isInUserRole)
                    {
                        return RedirectToAction("Member", "Home");
                    }
                    else if(isInAdminRole)
                    {
                        return RedirectToAction("Admin", "Home");
                    }
                    else
                    {
                        return RedirectToAction("AccessDenied");

                    }


                }
                else if(result.RequiresTwoFactor)
                {
                   return RedirectToAction("MFACheck");
                }
                else
                {
                    ModelState.AddModelError("login", "can not login");
                }
            }

            return View(model) ;
        }

        [HttpGet]
        public IActionResult MFACheck()
        {
            return View(new MFACheckViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> MFACheck(MFACheckViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, false, false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home", null);
                }
            }
            return View(model);
        }

        [HttpPost]
        public IActionResult ExternalLoginWithFacebook(string provider, string returnURL = null)
        {
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, returnURL);
            var callBackURL = Url.Action("ExternalLoginCallBack");
            properties.RedirectUri = callBackURL;
            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExternalLoginCallBack()
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();

            var emailClaim = info.Principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);

            if (emailClaim == null)
            {
                ModelState.AddModelError("", "ooops, No existing email on current provider's account");

                return RedirectToAction("AccessDenied");
            }
            
            var user = new IdentityUser { Email = emailClaim.Value, UserName = emailClaim.Value };

            var isUserExist = await userManager.FindByEmailAsync(user.Email);

            if(isUserExist == null)
            {
                var createUser = await userManager.CreateAsync(user);

                var linkFacebookToCurrentUser = await userManager.AddLoginAsync(user, info);
            }

            await _signInManager.SignInAsync(user,false); 

            return RedirectToAction("Home","Index");
        }
        public IActionResult AccessDenied()
        {
            return View();
        }

        public async Task<IActionResult> SignOut()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction("SignIn");
        }
    }
}
