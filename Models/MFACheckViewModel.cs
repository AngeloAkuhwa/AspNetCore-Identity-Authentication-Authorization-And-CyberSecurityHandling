using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityNetCore.Models
{
    public class MFACheckViewModel
    {
        [Required]
        public string Code { get; set; }

    }
}
