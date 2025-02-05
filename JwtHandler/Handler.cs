using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtHandler.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtHandler;

public static class Handler
{
  private static string? Issuer { get; set; }
  private static string? Audience { get; set; }
  private static string? Key { get; set; }
  private static string? RefreshKey { get; set; }
  private static string? EncryptionKey { get; set; }
  
  public static void SetSettings(JwtSettings settings) {
    Issuer = settings.Issuer;
    Audience = settings.Audience;
    Key = settings.Key;
    RefreshKey = settings.RefreshKey;
    EncryptionKey = settings.EncryptionKey;
  }

  public static TokenValidationParameters AccessValidationParameters() {
    if (Issuer == null || Audience == null || Key == null || EncryptionKey == null) throw new ArgumentNullException("Invalid configuration parameters");

    return new TokenValidationParameters
    {
      ValidateIssuer = true,
      ValidateAudience = true,
      ValidateLifetime = true,
      ValidateIssuerSigningKey = true,
      ValidIssuer = Issuer,
      ValidAudience = Audience,
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Key!)),
      TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(EncryptionKey!)),
    };
  }

  public static TokenValidationParameters RefreshValidationParameters() {
    if (Issuer == null || Audience == null || RefreshKey == null || EncryptionKey == null) throw new ArgumentNullException("Invalid configuration parameters");
    
    return new TokenValidationParameters
    {
      ValidateIssuer = true,
      ValidateAudience = true,
      ValidateLifetime = true,
      ValidateIssuerSigningKey = true,
      ValidIssuer = Issuer,
      ValidAudience = Audience,
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(RefreshKey!)),
      TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(EncryptionKey!)),
    };
  }

  public static string GenerateAccessToken(Guid userId, Guid sessionId, string role, CustomClaim[]? customClaims = null, int time = 5) {
    if (string.IsNullOrEmpty(Key) || Encoding.UTF8.GetBytes(Key!).Length < 32) throw new Exception("Invalid key");
    
    if (string.IsNullOrEmpty(EncryptionKey) || Encoding.UTF8.GetBytes(EncryptionKey!).Length != 32) throw new Exception("Invalid encryption key");

    SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(Key!));
    SigningCredentials credentials = new(key, SecurityAlgorithms.HmacSha256);

    Claim[] claims =
    [
        new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        new Claim(ClaimTypes.Role, role),
        new Claim(ClaimTypes.Sid, sessionId.ToString())
    ];

    if (customClaims != null) {
      foreach (CustomClaim claim in customClaims) {
        claims.Append(new Claim(claim.Name, claim.Value));
      }
    }

    ClaimsIdentity subject = new(claims);

    SymmetricSecurityKey encryptionKey = new(Encoding.UTF8.GetBytes(EncryptionKey!));
    EncryptingCredentials encryptingCredentials = new(encryptionKey, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512);

    JwtSecurityToken encryptedToken = new JwtSecurityTokenHandler().CreateJwtSecurityToken(
        issuer: Issuer,
        audience: Audience,
        subject: subject,
        notBefore: DateTime.Now,
        expires: DateTime.Now.AddMinutes(time),
        issuedAt: DateTime.Now,
        encryptingCredentials: encryptingCredentials,
        signingCredentials: credentials
    );

    return new JwtSecurityTokenHandler().WriteToken(encryptedToken);
  }

  public static string GenerateRefreshToken(Guid userId, Guid sessionId, string role, CustomClaim[]? customClaims = null, int time = 15) {
    if (string.IsNullOrEmpty(RefreshKey) || Encoding.UTF8.GetBytes(RefreshKey!).Length < 32) throw new Exception("Invalid key");
    
    if (string.IsNullOrEmpty(EncryptionKey) || Encoding.UTF8.GetBytes(EncryptionKey!).Length != 32) throw new Exception("Invalid encryption key");

    SymmetricSecurityKey key = new(Encoding.UTF8.GetBytes(RefreshKey!));
    SigningCredentials credentials = new(key, SecurityAlgorithms.HmacSha256);

    Claim[] claims =
    [
        new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        new Claim(ClaimTypes.Role, role),
        new Claim(ClaimTypes.Sid, sessionId.ToString())
    ];

    if (customClaims != null) {
      foreach (CustomClaim claim in customClaims) {
        claims.Append(new Claim(claim.Name, claim.Value));
      }
    }

    ClaimsIdentity subject = new(claims);

    SymmetricSecurityKey encryptionKey = new(Encoding.UTF8.GetBytes(EncryptionKey!));
    EncryptingCredentials encryptingCredentials = new(encryptionKey, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512);

    JwtSecurityToken encryptedToken = new JwtSecurityTokenHandler().CreateJwtSecurityToken(
        issuer: Issuer,
        audience: Audience,
        subject: subject,
        notBefore: DateTime.Now,
        expires: DateTime.Now.AddMinutes(time),
        issuedAt: DateTime.Now,
        encryptingCredentials: encryptingCredentials,
        signingCredentials: credentials
    );

    return new JwtSecurityTokenHandler().WriteToken(encryptedToken);
  }
}
