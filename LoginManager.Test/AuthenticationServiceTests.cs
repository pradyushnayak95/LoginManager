using FluentAssertions;
using LoginManager.Application.Dto;
using LoginManager.Application.Services;
using LoginManager.Core.Entities;
using LoginManager.Core.Interfaces;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace LoginManager.Test
{
    public class AuthenticationServiceTests
    {
        private readonly Mock<IUserRepository> _mockUserRepository;
        private readonly UserService _userService;

        public AuthenticationServiceTests()
        {
            _mockUserRepository = new Mock<IUserRepository>();
            _userService = new UserService(_mockUserRepository.Object);
        }

        [Fact]
        public async Task Authenticate_ShouldReturnUser_WhenCredentialsAreValid()
        {
            // Arrange
            var email = "nayakpradyush@gmail.com";
            var password = "123qwe";
            var hashpasswd = HashPassword(password);
            LoginUserDto loginDto = new LoginUserDto();
            loginDto.Email = email;
            loginDto.Password = password;
            

            var user = new User { Email = email };
            var userMock = new Mock<User>();
            userMock.Setup(u => u.ValidatePassword(password)).Returns(true);

            _mockUserRepository.Setup(repo => repo.GetUserByEmailAsync(email))
                               .ReturnsAsync(userMock.Object);
            // Act
            var result = await _userService.AuthenticateAsync(loginDto);

            // Assert
            result.Should().Be(user);
        }

        [Fact]
        public async Task Authenticate_ShouldThrowException_WhenUserDoesNotExist()
        {
            // Arrange
            var email = "invalidUser";
            var password = "password123";

            LoginUserDto loginDto = new LoginUserDto();
            loginDto.Email = email;
            loginDto.Password = password;

            _mockUserRepository.Setup(repo => repo.GetUserByEmailAsync(email))
                               .ReturnsAsync((User)null); // user not found

            // Act
            Func<Task> act = async () => await _userService.AuthenticateAsync(loginDto);

            // Assert
            await act.Should().ThrowAsync<InvalidCredentialException>()
                     .WithMessage("Invalid email or password.");
        }

        [Fact]
        public async Task Authenticate_ShouldThrowException_WhenPasswordIsInvalid()
        {
            // Arrange
            var email = "testUser@gmail.com";
            var password = "wrongPassword";

            LoginUserDto loginDto = new LoginUserDto();
            loginDto.Email = email;
            loginDto.Password = password;

            var userMock = new Mock<User>(); 
            userMock.Setup(u => u.ValidatePassword(password)).Returns(false); 

            _mockUserRepository.Setup(repo => repo.GetUserByEmailAsync(email))
                               .ReturnsAsync(userMock.Object);

            // Act
            Func<Task> act = async () => await _userService.AuthenticateAsync(loginDto);

            // Assert
            await act.Should().ThrowAsync<InvalidCredentialException>()
                     .WithMessage("Invalid username or password.");
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
    }
}
