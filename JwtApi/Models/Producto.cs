using System;
using System.Collections.Generic;

namespace JwtApi.Models;

public partial class Producto
{
    public int IdProducto { get; set; }

    public string Nombre { get; set; } = null!;

    public string Marca { get; set; } = null!;

    public decimal Precio { get; set; }
}
