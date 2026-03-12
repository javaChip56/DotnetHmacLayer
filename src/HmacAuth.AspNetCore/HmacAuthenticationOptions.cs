using Microsoft.AspNetCore.Authentication;

namespace HmacAuth.AspNetCore;

public sealed class HmacAuthenticationOptions : AuthenticationSchemeOptions
{
    public TimeSpan AllowedClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    public bool RequireNonceValidation { get; set; } = true;
}
