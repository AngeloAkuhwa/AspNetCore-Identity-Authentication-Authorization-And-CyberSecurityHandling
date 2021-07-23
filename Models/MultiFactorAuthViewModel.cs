using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityNetCore.Models
{
    public class MultiFactorAuthViewModel
    {
        public string Token { get; set; }
        public string Code { get; set; }
        public string QRCodeUrl { get; set; }
    }
}
