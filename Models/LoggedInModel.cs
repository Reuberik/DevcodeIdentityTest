using System;

namespace dotnet_core_mvc.Models
{
    public class LoggedInModel
    {
        public string Name { get; set; }
        public string FamilyName { get; set; }
        public string GivenName { get; set; }
        public string Gender { get; set; }
        public string Birthdate { get; set; }
        public string SSN { get; set; }
        public string SSNMask { get; set;}
        public string SignID { get; set; }
        public string Nonce { get; set; }
    }
}