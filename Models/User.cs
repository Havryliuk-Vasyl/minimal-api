﻿namespace FlamerService.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }

        public User(int id, string name, string email, string password)
        {
            Id = id;
            Name = name;
            Email = email;
            Password = password;
        }
    }

    public class UserAuthorization
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

}
