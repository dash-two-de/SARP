using System.Security.Claims;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web; // Add this using directive

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(options => {
        builder.Configuration.Bind("Authentication", options); 
    })
    .EnableTokenAcquisitionToCallDownstreamApi(options => {
        builder.Configuration.Bind("Authentication", options); 
    })
    .AddInMemoryTokenCaches();

builder.Services
    .AddAuthorization(options => {
        options.AddPolicy("default", policy =>
        {
            policy.RequireAuthenticatedUser();

            var allowedRoles = builder.Configuration.GetValue<string[]>("AllowedGroups") ?? Array.Empty<string>();
            if (allowedRoles.Length > 0) policy.RequireClaim(ClaimTypes.Role, allowedRoles);
        });
    });

builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

// Use authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.Map("/roles", (ClaimsPrincipal principal) =>
{
    // read all claims from the current principal and return them as a json
    // array with items containing the claim name and value as key/value
    var claims = principal.Claims.Select(c => new { c.Type, c.Value }).ToArray();
    return Results.Json(claims);
});

app.MapReverseProxy()
    .RequireAuthorization("default");

app.Run();
