namespace JwtHandler.Models
{
    public class JwtSettings
    {
        public required string Key { get; set; }
        public required string RefreshKey { get; set; }
        public required string EncryptionKey { get; set; }
        public required string Issuer { get; set; }
        public required string Audience { get; set; }
    }
}