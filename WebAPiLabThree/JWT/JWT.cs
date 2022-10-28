using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace WebAPiLabThree.JWT
{
    public  class JWT
    {
        public readonly IConfiguration _config;
        public JWT(IConfiguration config)
        {
            _config = config;
        }
        public SigningCredentials getCredentials()
        {
            String SecretKey = _config.GetValue<string>("SecretKey");
            byte[] KeyInBytes = Encoding.ASCII.GetBytes(SecretKey);
             SymmetricSecurityKey key = new SymmetricSecurityKey(KeyInBytes);
             SigningCredentials signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            return signingCredentials;
         }
        public SymmetricSecurityKey getKey()
        {
            String SecretKey = _config.GetValue<string>("SecretKey");
            byte[] KeyInBytes = Encoding.ASCII.GetBytes(SecretKey);
            SymmetricSecurityKey key = new SymmetricSecurityKey(KeyInBytes);
            return key;
        }
        //public static int tokenDuration = _config.GetValue<int>("tokenDuration");
    }
}
