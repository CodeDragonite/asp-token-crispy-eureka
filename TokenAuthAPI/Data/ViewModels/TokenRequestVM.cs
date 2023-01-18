using System.ComponentModel.DataAnnotations;

namespace TokenAuthAPI.Data.ViewModels
{
    public class LoginVM
    {
        
        [Required]
        public string? Email { get; set; }
        
        [Required]
        public string? Password { get; set; }
    }
}
