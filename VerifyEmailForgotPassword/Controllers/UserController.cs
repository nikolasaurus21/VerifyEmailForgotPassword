using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace VerifyEmailForgotPassword.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly DataContext _context;
        public UserController(DataContext context)
        {
            _context = context;
        }

        [HttpPost]

        public async Task<ActionResult> Register(UserRegistrationRequest request)
        {
            if(_context.Users.Any(x => x.Email == request.Email))
            {
                return BadRequest("User already exsist");

            }

            CreatePasswordHash(request.Password,
                out byte[] passwordHash,
                out byte[] passwordSalt);

            var user = new User {
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                VerificationToken = CreateRandomToken()

            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return Ok("User successfully created");
        }

        [HttpPost]

        public async Task<ActionResult> Login(UserLoginRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == request.Email);
            if (user == null)
            {
                return BadRequest("User not found");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }
            
            if (user.VerifiedAt == null)
            {
                return BadRequest("Not verified");
            }


            return Ok($"Welcome back, {user.Email}");
        }

        [HttpPost]
        
        public async Task<ActionResult> Verify(string token)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.VerificationToken == token);
            if (user == null)
            {
                return BadRequest("Invalid token");
            }

            user.VerifiedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            return Ok("User verified");
        }

        [HttpPost]
        public async Task<ActionResult> ForgotPassword(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == email);
            if (user == null)
            {
                return BadRequest("User not found");
            }

            user.PasswordResetToken = CreateRandomToken();
            user.ResetTokenExpires = DateTime.UtcNow.AddDays(1);
            await _context.SaveChangesAsync();
            return Ok("You may now reset ypur password");
        }
        [HttpPost]
        public async Task<ActionResult> ResetPassword(ResetPasswordRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.PasswordResetToken == request.Token);
            if (user == null || user.ResetTokenExpires < DateTime.UtcNow)
            {
                return BadRequest("Invalid token");
            }

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;
            await _context.SaveChangesAsync();
            return Ok("Password successfully reset");

        }
        

        private void CreatePasswordHash(string password, out byte[] passwordHash,out byte[] passwordSalt)
        {
            // ovo sluzi za kriptovanje passworda
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        //sluzi za kreirtanje verificationtokena
        private string CreateRandomToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        }
    }
}
