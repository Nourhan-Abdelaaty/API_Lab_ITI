using Microsoft.AspNetCore.Identity;

namespace WebAPiLabThree.Data.Models
{
    public class Employee:IdentityUser
    {
        public string Department { get; set; } = "";
    }
}
