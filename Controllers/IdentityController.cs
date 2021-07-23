using IdentityNetCore.Models;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
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

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> MultiFactorAuthenticationSetUp()
        {
            const string provider = "asp.netIdentity";
            var loggedInUser = await userManager.GetUserAsync(User);

            await userManager.ResetAuthenticatorKeyAsync(loggedInUser);

            var token = await userManager.GetAuthenticatorKeyAsync(loggedInUser);

            var qrCodeUrl = $"otpauth://totp/{provider}:{loggedInUser.Email}?secret={token}&issuer={provider}&digits=6";

            MultiFactorAuthViewModel multiFactorAuth = new MultiFactorAuthViewModel { Token = token,QRCodeUrl =qrCodeUrl };

            return View(multiFactorAuth);
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> MultiFactorAuthenticationSetUp(MultiFactorAuthViewModel model)
        {
            var loggedInUser = await userManager.GetUserAsync(User);

           var succeeded = await userManager.VerifyTwoFactorTokenAsync(loggedInUser, userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
            if (succeeded)
            {
                await userManager.SetTwoFactorEnabledAsync(loggedInUser,true); 
            }
            else
            {
                ModelState.AddModelError("Verify","Your MFA code could not be validated");
            }


            return View(model);
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
                if (result.Succeeded)
                {
                    var user = await userManager.FindByEmailAsync(model.UserName);

                    var userClaims = await userManager.GetClaimsAsync(user);

                    if(!userClaims.Any(x => x.Type == "Department"))
                    {
                        ModelState.AddModelError("Department", "user does not have a department");
                        return View(model);
                    }

                    if(await userManager.IsInRoleAsync(user, "Member"))
                    {
                        return RedirectToAction("Member", "Home");
                    }

                   
                }
                else
                {
                    ModelState.AddModelError("login", "can not login");
                }
            }

            return View(model) ;
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
