using Account_Authentication_Module_API.EmailManagement.Services;
using Account_Authentication_Module_API.EmailManagement;
using Account_Authentication_Module_API.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using System;
using Microsoft.EntityFrameworkCore;
using Account_Authentication_Module_API.Services;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Account_Authentication_Module_API
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

            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Account_Authentication_Module_API", Version = "v1" });
            });


            //register Identity servise to can use Identity Users and Roles.
            services.AddIdentity<User, IdentityRole>().AddEntityFrameworkStores<DataContext>().AddDefaultTokenProviders();

            //register DbContext to can connect with database.
            services.AddDbContext<DataContext>(options => options.UseSqlServer(Configuration.GetConnectionString("sql")));

            //register email configrations from appsettings.json file to EmailConfigration class. 
            services.AddSingleton(Configuration.GetSection("EmailConfigration").Get<EmailConfigration>());

            //register MailService service to can inject it.
            services.AddScoped<IEmailServices, EmailServices>();
            services.AddScoped<IAccountAuthenticationRepository, AccountAuthenticationRepository>();

            //add confir for confirmation email.
            services.Configure<IdentityOptions>(options => options.SignIn.RequireConfirmedEmail = true);

            //reset password token.
            services.Configure<DataProtectionTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromHours(2));

            //register Authentication service to can use [Authorize] use JWT token in check authentication.
            services.AddAuthentication(options => { }).AddJwtBearer(options =>
            {
                //check for token save or not
                options.SaveToken = true;
                //check for Http
                options.RequireHttpsMetadata = false;
                //valid parameters can deal with API
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidIssuer = Configuration["JWT:ValidIssuer"],

                    ValidateAudience = true,
                    ValidAudience = Configuration["JWT:ValidAudience"],

                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JWT:SecretKey"]))
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Account_Authentication_Module_API v1"));
            }

            app.UseRouting();

            // to check token when login
            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
