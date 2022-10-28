using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebAPiLabThree.Data.Models;

namespace WebAPiLabThree.Data.Context
{
    public class ApplicationDbContext:IdentityDbContext<Employee>
    {
        public ApplicationDbContext(DbContextOptions options):base(options)
        {
        }
        public DbSet<Employee> Employees { get; set; }
    }
}
