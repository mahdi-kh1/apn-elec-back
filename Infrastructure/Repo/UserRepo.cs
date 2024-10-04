using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Application.Contracts;
using Application.DTOs;
using Domain.Entities;
using Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Repo;

internal class UserRepo : IUser
{
    private readonly AppDbContext appDbContext;
    private readonly IConfiguration configuration;

    public UserRepo(AppDbContext appDbContext, IConfiguration configuration)
    {
        this.appDbContext = appDbContext;
        this.configuration = configuration;
        
    }

    private async Task<SysUser> FindUserByEmailAsync(string email)
    {
        return await appDbContext.Users.FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<LoginResponse> LoginUserAsync(LoginDTO loginDTO)
    {
        var getUser = await FindUserByEmailAsync(loginDTO.Email!);
        if (getUser == null)
            return new LoginResponse(false, "User not found");
        bool checkPassword = BCrypt.Net.BCrypt.Verify(loginDTO.Password, getUser.Password);
        if (checkPassword)
            return new LoginResponse(true, "Login successful", GenerateJwtToken(getUser));
        else
            return new LoginResponse(false, "Invalid Credentials");
    }

    private string GenerateJwtToken(SysUser user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms. HmacSha256);
        var userClaims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.FirstName!),
            new Claim(ClaimTypes.Name, user.LastName!),
            new Claim(ClaimTypes.Email, user.Email!)
        };
        var token = new JwtSecurityToken(
            issuer: configuration["Jwt: Issuer"],
            audience: configuration["Jwt:Audience"],
            claims: userClaims,
            expires: DateTime.Now.AddDays(5),
            signingCredentials: credentials
            );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<RegistrationResponse> RegisterUserAsync(RegisterUserDTO registerUserDTO)
    {
        var getUser = await FindUserByEmailAsync(registerUserDTO.Email!);
        if (getUser != null)
            return new RegistrationResponse(false, "Email already exists");
        appDbContext.Users.Add(
            new SysUser()
            {
                FirstName = registerUserDTO.FirstName,
                LastName = registerUserDTO.LastName,
                Email = registerUserDTO.Email!,
                Password = BCrypt.Net.BCrypt.HashPassword(registerUserDTO.Password),
            }
        );
        await appDbContext.SaveChangesAsync();
        return new RegistrationResponse(true, "Registration completed");
    }
}
