using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using TokenAuthAPI.Data;
using TokenAuthAPI.Data.Models;

var builder = WebApplication.CreateBuilder(args);
string connString = builder.
        Configuration.
        GetConnectionString("DefaultConnection");// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(connString);
});

var tokeValidationParams = new TokenValidationParameters()
{
    ValidateIssuerSigningKey = true,
    //IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(builder.Configuration["Jwt.Secret"])),
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("this-is-the-secret-used-for-some-tokens-i-think-or-not")),
    ValidateIssuer = true,
    ValidIssuer = "https://localhost:44335", //builder.Configuration["Jwt.Issuer"],
    ValidateAudience = true,
    ValidAudience = "user", //builder.Configuration["Jwt.Audience"]
    ValidateLifetime = true,
    ClockSkew = TimeSpan.Zero
};
builder.Services.AddSingleton(tokeValidationParams);

builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;


    options.TokenValidationParameters = tokeValidationParams;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

AppDbInitializer.SeedRolesToDb(app).Wait();

app.Run();
