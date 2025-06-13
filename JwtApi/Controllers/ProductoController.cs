using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using JwtApi.Models;
using Microsoft.AspNetCore.Authorization;


namespace JwtApi.Controllers
{
    [Route("api/[controller]")]
    [Authorize] // A esta Api solo la usan usuarios autorizados
    [ApiController]
    public class ProductoController : ControllerBase
    {
        private readonly PruebaJwtContext _jwtContext;
        public ProductoController(PruebaJwtContext jwtContext)
        {
            _jwtContext = jwtContext;
        }

        [HttpGet]
        [Route("Lista")]
        public async Task <IActionResult> Lista()
        {
            var lista = await _jwtContext.Productos.ToListAsync();
            return StatusCode(StatusCodes.Status200OK,new {value = lista});
        }
    }
}
