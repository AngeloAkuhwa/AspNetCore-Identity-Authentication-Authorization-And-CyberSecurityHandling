using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityNetCore.Models
{
    public class SignUpViewModel
    {
        [Required]
        [DataType(DataType.EmailAddress, ErrorMessage ="Invalid or missing mail")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password, ErrorMessage = "Invalid or missing password")]
        public string PassWord { get; set; }

        [Required]
        public string Role { get; set; }

        [Required]
        public string Department { get; set; }

    }
}
