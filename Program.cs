using FlamerService.Authorization;
using FlamerService.Endpoints;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JWTSettings>(builder.Configuration.GetSection("JWTSettings"));

var secretKey = builder.Configuration.GetSection("JWTSettings:SecretKey").Value;
var issuer = builder.Configuration.GetSection("JWTSettings:Issuer").Value;
var audience = builder.Configuration.GetSection("JWTSettings:Audience").Value;

JWTSettings jWTSettings = new JWTSettings(secretKey, issuer, audience);

var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateLifetime = true,
        IssuerSigningKey = signingKey,
        ValidateIssuerSigningKey = true
    };
});
builder.Services.AddAuthorization();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});

var app = builder.Build();

app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();

app.RegisterUserEndpoints(jWTSettings);

app.Run();
