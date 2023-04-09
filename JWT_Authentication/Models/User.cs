namespace JWT_Authentication.Models
{
    public class User
    {
        public string username { get; set; } = string.Empty;
        public byte[] passwordHash { get; set; }
        public byte[] passwordSalt { get; set; }
    }
}
