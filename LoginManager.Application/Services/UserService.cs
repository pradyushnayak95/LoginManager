using LoginManager.Application.Dto;
using LoginManager.Core.Entities;
using LoginManager.Core.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LoginManager.Application.Services
{
    public class UserService
    {
        private readonly IUserRepository _userRepository;

        public UserService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public async Task<bool> RegisterUserAsync(RegisterDto userDto)
        {
            if (string.IsNullOrWhiteSpace(userDto.Username))
            {
                throw new ArgumentException("Username is required.");
            }

            if (string.IsNullOrWhiteSpace(userDto.Password))
            {
                throw new ArgumentException("Password is required.");
            }

            var existingEmail = await _userRepository.GetUserByEmailAsync(userDto.Email);
            if (existingEmail != null)
            {
                throw new ArgumentException("Email already exists.");
            }
            var user = new User
            {
                Username = userDto.Username,
                PasswordHash = HashPassword(userDto.Password),
                Email = userDto.Email
            };

            return await _userRepository.AddUserAsync(user);
        }

        public async Task<User> AuthenticateAsync(LoginUserDto loginDto)
        {
                var user = await _userRepository.GetUserByEmailAsync(loginDto.Email);
                if (user == null || !VerifyPassword(loginDto.Password, user.PasswordHash))
                {
                    return null; 
                }
            
            return user;
        }

        private string HashPassword(string password)
        {
           
            byte[] salt = new byte[16];
            RandomNumberGenerator.Fill(salt);

            // Hash the password with the salt using PBKDF2
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000); 
            byte[] hash = pbkdf2.GetBytes(20); 

            // Combine the salt and hash
            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            
            return Convert.ToBase64String(hashBytes);
        }

        private bool VerifyPassword(string password, string hash)
        {
           
            byte[] hashBytes = Convert.FromBase64String(hash);

            
            byte[] salt = new byte[16];
            Array.Copy(hashBytes, 0, salt, 0, 16);

            
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000);
            byte[] rhash = pbkdf2.GetBytes(20);

           
            for (int i = 0; i < 20; i++)
            {
                if (hashBytes[i + 16] != rhash[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
