using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using JwtApi.Custom;
using JwtApi.Models;
using JwtApi.Models.DTOs;
using Microsoft.AspNetCore.Authorization;

namespace JwtApi.Controllers
{
    [Route("api/[controller]")]
    [AllowAnonymous] //al ser el controlador de acceso el usuario no tiene que estar autenticado
    [ApiController]
    public class AccesoController : ControllerBase
    {
        private readonly PruebaJwtContext _jwtContext;
        private readonly Utilidades _utilidades;
        public AccesoController(PruebaJwtContext jwtContext, Utilidades utilidades)
        {
            _jwtContext = jwtContext;
            _utilidades = utilidades;
        }

        [HttpPost]
        [Route("Registrarse")]
        public async Task<IActionResult> Registrarse(UsuarioDTO objeto)
        {
            var modeloUsuario = new Usuario
            {
                Nombre = objeto.Nombre,
                Correo = objeto.Correo,
                Clave = _utilidades.encriptarSHA256(objeto.Clave)
            };

            await _jwtContext.Usuarios.AddAsync(modeloUsuario);
            await _jwtContext.SaveChangesAsync();

            if(modeloUsuario.IdUsuario != 0)
                return StatusCode(StatusCodes.Status200OK, new {isSuccess = true});
            else
                return StatusCode(StatusCodes.Status200OK, new { isSuccess = false});
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginDTO objeto)
        {
            var usuarioEncontrado = await _jwtContext.Usuarios.Where(u => u.Correo == objeto.Correo 
                                                                        && u.Clave == _utilidades.encriptarSHA256(objeto.Clave)).FirstOrDefaultAsync();

            if(usuarioEncontrado == null)
                return StatusCode(StatusCodes.Status200OK, new { isSuccess = false, token = "" });
            else
                return StatusCode(StatusCodes.Status200OK, new { isSuccess = true, token = _utilidades.generarJWT(usuarioEncontrado)});
        }

        [HttpGet]
        [Route("ValidarToken")]
        public IActionResult ValidarToken([FromQuery]string token)
        {
            bool respuesta = _utilidades.ValidarToken(token);
            return StatusCode(StatusCodes.Status200OK, new { isSuccess = respuesta });           
        }
    }
}
