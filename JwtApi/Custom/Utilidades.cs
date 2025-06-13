using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtApi.Models;

namespace JwtApi.Custom
{
    public class Utilidades
    {
        private readonly IConfiguration _configuration; // lee las propiedades del appsettings.json
        public Utilidades(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        /// <summary>
        /// Encripta la contraseña
        /// </summary>
        /// <param name="texto"></param>
        /// <returns></returns>
        public string encriptarSHA256(string texto)
        {
            using (SHA256 sha256Hash = SHA256.Create()) 
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(texto));
                
                StringBuilder builder = new StringBuilder();

                for (int i = 0; i < bytes.Length; i++) 
                { 
                    builder.Append(bytes[i].ToString("X2"));
                }

                return builder.ToString();
            }
        }

        /// <summary>
        /// Genera el token
        /// </summary>
        /// <param name="modelo"></param>
        /// <returns></returns>
        public string generarJWT(Usuario modelo)
        {
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, modelo.IdUsuario.ToString()),
                new Claim(ClaimTypes.Email,modelo.Correo) //Si se necesita mas informacion del usuario se agrega acá
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:key"]!));
            var credentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256Signature);

            //info token

            var jwtConfig = new JwtSecurityToken(
                claims: userClaims,
                expires: DateTime.UtcNow.AddMinutes(10), //cuando expira el token
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(jwtConfig);
        }

        public bool ValidarToken(string token)
        {
            ClaimsPrincipal claimPrincipal = new ClaimsPrincipal();
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = false, //valida la url
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:key"]!))
            };

            try
            {
                claimPrincipal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validationToken);
                return true;
            }

            catch (Exception ex)
            { 
                return false;
            }

        }
    }
}
