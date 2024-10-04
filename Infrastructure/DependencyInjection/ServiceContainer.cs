﻿using System.Text;
using Application.Contracts;
using Infrastructure.Data;
using Infrastructure.Repo;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.DependencyInjection
{
    public static class ServiceContainer
    {
        public static IServiceCollection InfrastructureServices(
            this IServiceCollection services,
            IConfiguration configuration
        )
        {
            services.AddDbContext<AppDbContext>(
                options =>
                    options.UseSqlServer(
                        configuration.GetConnectionString("Default"),
                        b => b.MigrationsAssembly(typeof(ServiceContainer).Assembly.FullName)
                    ),
                ServiceLifetime.Scoped
            );
            services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateIssuerSigningKey = true,
                        ValidateLifetime = true,
                        ValidIssuer = configuration["Jwt : Issuer"],
                        ValidAudience = configuration["Jwt :Audience"],
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(configuration["Jwt :Key"]!)
                        ),
                    };
                });
            services.AddScoped<IUser, UserRepo>();
            return services;
        }
    }
}
