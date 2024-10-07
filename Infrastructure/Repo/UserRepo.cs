// Importing necessary namespaces for the application.
using System.IdentityModel.Tokens.Jwt; // For handling JWT tokens.
using System.Security.Claims; // For using claims in the JWT token.
using System.Text; // For encoding.
using Application.Contracts; // For application contract interfaces.
using Application.DTOs; // For Data Transfer Objects used in the application.
using Domain.Entities; // For domain entities like SysUser.
using Infrastructure.Data; // For database context.
using Microsoft.EntityFrameworkCore; // For Entity Framework Core functionalities.
using Microsoft.Extensions.Configuration; // For configuration management.
using Microsoft.IdentityModel.Tokens; // For security token management.

namespace Infrastructure.Repo
{
    // The UserRepo class implements IUser interface for user-related database operations.
    internal class UserRepo : IUser
    {
        private readonly AppDbContext appDbContext; // The database context for accessing user data.
        private readonly IConfiguration configuration; // Configuration settings for the application.

        // Constructor that initializes the UserRepo class with the AppDbContext and IConfiguration.
        public UserRepo(AppDbContext appDbContext, IConfiguration configuration)
        {
            this.appDbContext = appDbContext; // Assigning the passed AppDbContext to the class variable.
            this.configuration = configuration; // Assigning the passed IConfiguration to the class variable.
        }

        // Method to find a user by their email asynchronously.
        private async Task<SysUser> FindUserByEmailAsync(string email)
        {
            return await appDbContext.Users.FirstOrDefaultAsync(u => u.Email == email);
            // Searches for the first user with the given email in the database.
        }

        // Method for user login that returns a LoginResponse object.
        public async Task<LoginResponse> LoginUserAsync(LoginDTO loginDTO)
        {
            var getUser = await FindUserByEmailAsync(loginDTO.Email!); // Finds the user by email.
            if (getUser == null)
                return new LoginResponse(false, "User not found"); // Returns failure response if user is not found.

            // Validates the password using BCrypt.
            bool checkPassword = BCrypt.Net.BCrypt.Verify(loginDTO.Password, getUser.Password);
            if (checkPassword)
                return new LoginResponse(true, "Login successful", GenerateJwtToken(getUser)); // Returns success response and JWT token if password matches.
            else
                return new LoginResponse(false, "Invalid Credentials"); // Returns failure response if password does not match.
        }

        // Method to generate a JWT token for a given user.
        private string GenerateJwtToken(SysUser user)
        {
            var securityKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!) // Retrieves the secret key from configuration.
            );
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256); // Sets the signing credentials using HMAC SHA256.

            // Creating claims for the user.
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), // User ID as name identifier.
                new Claim(ClaimTypes.Name, user.FirstName!), // User first name.
                new Claim(ClaimTypes.Name, user.LastName!), // User last name.
                new Claim(ClaimTypes.Email, user.Email!), // User email.
            };

            // Creating a new JWT token.
            var token = new JwtSecurityToken(
                issuer: configuration["Jwt: Issuer"], // Retrieves the token issuer from configuration.
                audience: configuration["Jwt:Audience"], // Retrieves the audience from configuration.
                claims: userClaims, // Claims associated with the user.
                expires: DateTime.Now.AddMinutes(120), // Sets the expiration time for the token.
                signingCredentials: credentials // Uses the signing credentials.
            );

            return new JwtSecurityTokenHandler().WriteToken(token); // Serializes the token to a string format.
        }

        // Method for user registration that returns a RegistrationResponse object.
        public async Task<RegistrationResponse> RegisterUserAsync(RegisterUserDTO registerUserDTO)
        {
            var getUser = await FindUserByEmailAsync(registerUserDTO.Email!); // Checks if the user already exists by email.
            if (getUser != null)
                return new RegistrationResponse(false, "Email already exists"); // Returns failure response if email is taken.

            // Creates a new user entity and adds it to the database.
            appDbContext.Users.Add(
                new SysUser()
                {
                    FirstName = registerUserDTO.FirstName, // Assigns the first name.
                    LastName = registerUserDTO.LastName, // Assigns the last name.
                    Email = registerUserDTO.Email!, // Assigns the email.
                    Password = BCrypt.Net.BCrypt.HashPassword(registerUserDTO.Password), // Hashes the password for security.
                }
            );

            await appDbContext.SaveChangesAsync(); // Saves the new user to the database.
            return new RegistrationResponse(true, "Registration completed"); // Returns success response.
        }
    }
}
