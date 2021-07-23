﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityNetCore.Models
{
    public class SignInViewModel
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password  { get; set; }
        [Required]
        public bool RememberMe  { get; set; }

    }
}
