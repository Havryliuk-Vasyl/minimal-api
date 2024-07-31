using FlamerService.Authorization;
using FlamerService.Models;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace FlamerService.Endpoints
{
    public static class Users
    {
        public static void RegisterUserEndpoints(this IEndpointRouteBuilder routes, JWTSettings options)
        {
            var users = new ConcurrentBag<User>();

            var usersRouter = routes.MapGroup("/api/v1/users");
            var usersRouterAuthorizated = routes.MapGroup("/api/v1/usersAuthorizated").RequireAuthorization();

            usersRouter.MapPost("/registration", async (HttpContext context) =>
            {
                var user = await context.Request.ReadFromJsonAsync<User>();

                if (user == null || string.IsNullOrWhiteSpace(user.Name) || string.IsNullOrWhiteSpace(user.Email) || string.IsNullOrWhiteSpace(user.Password))
                {
                    return Results.BadRequest("Invalid user data.");
                }

                user.Id = users.Count();
                users.Add(user);

                return Results.Ok(new { message = "User registered successfully." });
            });

            usersRouter.MapPost("/authorization", (HttpContext context) =>
            {
                var user = context.Request.ReadFromJsonAsync<UserAuthorization>().Result;

                if (user == null || string.IsNullOrWhiteSpace(user.Email) || string.IsNullOrWhiteSpace(user.Password))
                {
                    return Results.BadRequest("Invalid user data.");
                }

                var existingUser = users.FirstOrDefault(u => u.Email == user.Email && u.Password == user.Password);

                if (existingUser == null)
                {
                    return Results.Unauthorized();
                }

                AuthentificationModel authentificationModel = new AuthentificationModel(options);
                string tokenString = authentificationModel.GetToken(existingUser);

                return Results.Ok(new { token = tokenString });
            });
            

            usersRouterAuthorizated.MapGet("/users", () =>
            {
                return Results.Ok(users);
            });

            usersRouterAuthorizated.MapGet("/account", (HttpContext context) =>
            {
                if (context.Request.Query.TryGetValue("userId", out var userIdString) && int.TryParse(userIdString, out int userId))
                {
                    var user = users.FirstOrDefault(u => u.Id == userId);

                    if (user != null)
                    {
                        return Results.Ok(user);
                    }
                    else
                    {
                        return Results.NotFound("User not found");
                    }
                }
                else
                {
                    return Results.BadRequest("Invalid or missing userId parameter");
                }
            });
        }
    }

    public class AuthentificationModel
    {
        private readonly JWTSettings _options;

        public AuthentificationModel(JWTSettings options)
        {
            _options = options;
        }

        public string GetToken(User user)
        {
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("ID", user.Id.ToString()));
            claims.Add(new Claim(ClaimTypes.Name, user.Name));
            claims.Add(new Claim(ClaimTypes.Email, user.Email));

            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SecretKey));

            var jwt = new JwtSecurityToken(
                    issuer: _options.Issuer,
                    audience: _options.Audience,
                    claims: claims,
                    expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(1)),
                    signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
    }
}
