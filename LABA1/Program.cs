using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace LABA1
{
    public enum RegistrationResult
    {
        Success,
        EmailAlreadyExists,
        InvalidEmail,
        WeakPassword
    }

    public enum PasswordResetResult
    {
        Success,
        UserNotFound,
        InvalidToken,
        TokenExpired
    }

    class User
    {
        public string Email { get; set; }
        public string PasswordHash { get; set; }

        public string? RecoveryToken { get; set; }
        public DateTime? RecoveryTokenExpiration { get; set; }
    }

    class UserManager
    {
        private List<User> users = new List<User>();

        public RegistrationResult RegisterUser(string email, string password)
        {
            if (!IsValidEmail(email)) return RegistrationResult.InvalidEmail;
            if (!IsStrongPassword(password)) return RegistrationResult.WeakPassword;
            if (users.Any(user => user.Email.Equals(email, StringComparison.OrdinalIgnoreCase)))
            {
                return RegistrationResult.EmailAlreadyExists;
            }

            var passwordHash = HashPassword(password);
            users.Add(new User { Email = email, PasswordHash = passwordHash });
            return RegistrationResult.Success;
        }

        public bool LoginUser(string email, string password)
        {
            var user = FindUserByEmail(email);
            if (user != null)
            {
                var inputPasswordHash = HashPassword(password);
                return user.PasswordHash == inputPasswordHash;
            }
            return false;
        }

        public string? InitiatePasswordRecovery(string email)
        {
            var user = FindUserByEmail(email);
            if (user == null)
            {
                return null;
            }

            user.RecoveryToken = Guid.NewGuid().ToString();
            user.RecoveryTokenExpiration = DateTime.UtcNow.AddMinutes(10);

            return user.RecoveryToken;
        }

        public PasswordResetResult ResetPassword(string token, string newPassword)
        {
            if (!IsStrongPassword(newPassword))
            {
                return PasswordResetResult.InvalidToken;
            }

            var user = users.FirstOrDefault(u => u.RecoveryToken == token);

            if (user == null)
            {
                return PasswordResetResult.InvalidToken;
            }

            if (user.RecoveryTokenExpiration < DateTime.UtcNow)
            {
                user.RecoveryToken = null;
                user.RecoveryTokenExpiration = null;
                return PasswordResetResult.TokenExpired;
            }

            user.PasswordHash = HashPassword(newPassword);

            user.RecoveryToken = null;
            user.RecoveryTokenExpiration = null;

            return PasswordResetResult.Success;
        }

        public bool IsStrongPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 8) return false;
            return password.Any(char.IsUpper) && password.Any(char.IsLower) && password.Any(char.IsDigit);
        }

        private User? FindUserByEmail(string email)
        {
            return users.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            try
            {
                return Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
            }
            catch (RegexMatchTimeoutException) { return false; }
        }

        private string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }
    }

    class Program
    {
        static void Main()
        {
            UserManager userManager = new UserManager();

            while (true)
            {
                Console.WriteLine("\nВыберите действие:\n1 - Регистрация\n2 - Вход\n3 - Восстановить пароль\n0 - Выход");
                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        Register(userManager);
                        break;
                    case "2":
                        Login(userManager);
                        break;
                    case "3":
                        RecoverPassword(userManager);
                        break;
                    case "0":
                        return;
                    default:
                        Console.WriteLine("Некорректный ввод. Попробуйте снова.");
                        break;
                }
            }
        }

        static void Register(UserManager userManager)
        {
            Console.WriteLine("Введите адрес электронной почты:");
            string regEmail = Console.ReadLine();
            Console.WriteLine("Введите пароль (минимум 8 символов, заглавная, строчная буквы и цифра):");
            string regPassword = Console.ReadLine();

            RegistrationResult result = userManager.RegisterUser(regEmail, regPassword);
            switch (result)
            {
                case RegistrationResult.Success:
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Пользователь успешно зарегистрирован!");
                    break;
                case RegistrationResult.InvalidEmail:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Ошибка: Некорректный формат электронной почты.");
                    break;
                case RegistrationResult.WeakPassword:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Ошибка: Пароль слишком простой.");
                    break;
                case RegistrationResult.EmailAlreadyExists:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Ошибка: Пользователь с таким email уже существует.");
                    break;
            }
            Console.ResetColor();
        }

        static void Login(UserManager userManager)
        {
            Console.WriteLine("Введите адрес электронной почты:");
            string loginEmail = Console.ReadLine();
            Console.WriteLine("Введите пароль:");
            string loginPassword = Console.ReadLine();

            if (userManager.LoginUser(loginEmail, loginPassword))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Вход выполнен успешно!");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Ошибка: Неверный адрес электронной почты или пароль.");
            }
            Console.ResetColor();
        }

        static void RecoverPassword(UserManager userManager)
        {
            Console.WriteLine("--- Восстановление пароля ---");
            Console.WriteLine("Введите email зарегистрированного пользователя:");
            string email = Console.ReadLine();

            string? token = userManager.InitiatePasswordRecovery(email);

            if (token == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Пользователь с таким email не найден.");
                Console.ResetColor();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("На вашу почту было отправлено письмо с кодом восстановления (действует 10 минут).");
            Console.WriteLine($"Ваш код восстановления: {token}");
            Console.ResetColor();

            Console.WriteLine("\nПожалуйста, введите полученный код восстановления:");
            string inputToken = Console.ReadLine();

            Console.WriteLine("Введите новый пароль (минимум 8 символов, заглавная, строчная буквы и цифра):");
            string newPassword = Console.ReadLine();
            Console.WriteLine("Подтвердите новый пароль:");
            string confirmPassword = Console.ReadLine();

            if (newPassword != confirmPassword)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Пароли не совпадают. Попробуйте снова.");
                Console.ResetColor();
                return;
            }

            if (!userManager.IsStrongPassword(newPassword))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Ошибка: Новый пароль слишком простой.");
                Console.ResetColor();
                return;
            }


            PasswordResetResult result = userManager.ResetPassword(inputToken, newPassword);

            switch (result)
            {
                case PasswordResetResult.Success:
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Пароль успешно изменен!");
                    Console.ResetColor();
                    Console.WriteLine("Теперь вы можете войти в систему с новым паролем.");
                    break;
                case PasswordResetResult.InvalidToken:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Ошибка: Неверный код восстановления.");
                    Console.ResetColor();
                    break;
                case PasswordResetResult.TokenExpired:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Ошибка: Код восстановления истек. Пожалуйста, запросите новый.");
                    Console.ResetColor();
                    break;
            }
        }
    }
}