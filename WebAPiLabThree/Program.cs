using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using WebAPiLabThree.Data.Context;
using WebAPiLabThree.Data.Models;
using WebAPiLabThree.JWT;

namespace WebAPiLabThree
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();
            //Context configurations
            builder.Services.AddDbContext<ApplicationDbContext>(opt =>
            {
                opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
            });
            //Manager configurations
            #region Manager Configuration
            builder.Services.AddIdentity<Employee, IdentityRole>(options =>
                {
                    options.User.RequireUniqueEmail = false;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Lockout.MaxFailedAccessAttempts = 3;
                    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
                }).AddEntityFrameworkStores<ApplicationDbContext>();
            #endregion
            //To inject iConfiguration
            builder.Services.AddSingleton<IConfiguration>(builder.Configuration);

            //Authentication configurations
            #region Authentication
            builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Default";
                    options.DefaultChallengeScheme = "Default";
                }).AddJwtBearer("Default", options =>
                {
                    //var key = WebAPiLabThree.JWT.JWT.key;
                    //var keyString = builder.Configuration.GetValue<string>("SecretKey");
                    //var keyInBytes = Encoding.ASCII.GetBytes(keyString);
                    //var key = new SymmetricSecurityKey(keyInBytes);
                    JWT.JWT myJwt = new JWT.JWT(builder.Configuration);
                    var key = myJwt.getKey();
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = key,
                        ValidateIssuer = false,
                        ValidateAudience = false
                    };
                });

            #endregion
            //Adding new policy
            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("CEO", p => p.RequireClaim(claimType: ClaimTypes.Role, "CEO"));
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            //We must add authentication before authorization
            app.UseAuthentication();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}