using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IdentityNetCore.Data;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace IdentityNetCore
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var configuration = Configuration["ConnectionStrings:default"];
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(configuration));
            services.AddIdentity<IdentityUser,IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options => {
                options.Password.RequiredLength = 3;
                options.Password.RequireNonAlphanumeric = false;
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
               // options.SignIn.RequireConfirmedEmail = true;
            
            });

            services.Configure<SmtpOptions>(Configuration.GetSection("Smtp"));

            services.AddScoped<IEmailSender, SmtpEmailSender>();

            services.AddAuthorization(options =>
            {
                options.AddPolicy("MemberDepartment", policy =>
                {

                    policy.RequireClaim("Department", "Tech").RequireRole("Member");

                });

                options.AddPolicy("AdminDepartment", policy =>
                {

                    policy.RequireClaim("Department", "Tech").RequireRole("Admin");

                });
            });

            services.AddAuthorization();

            services.AddAuthentication().AddFacebook(options => {

                options.AppId = Configuration["FacebookAppId"];
                options.AppSecret = Configuration["FacebookAppSecret"];
            });

            services.AddControllersWithViews();

            services.ConfigureApplicationCookie(options => {
                options.LoginPath = "/Identity/SignIn";
                options.AccessDeniedPath = "/Identity/AccessDenied";
   

            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();
           
           
            app.UseAuthentication();

            app.UseAuthorization();
           

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
