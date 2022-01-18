using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using dotnet_core_mvc.Models;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Net.Http;
using IdentityModel.Client;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Newtonsoft.Json;
using Microsoft.Owin.Security;

namespace dotnet_core_mvc.Controllers {
    public class HomeController : Controller {
        // TODO: store these settings in appsettings.json or similar
        private string hostURL = "https://test-api.paymentiq.io"; // TODO: use https://api.gii.cloud for production
        private string key = "Q2ONoncZ5S57UVWeu04zuW5WZh"; // TODO: generate your own random string
        //private string clientId = "74698bec9c364deebd4ce3bb1a17f916"; // TODO: use your clientId
        //private string clientSecret = "750dfa4b45d449a5a082606f59d203b5"; // TODO: use your API-key
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat;
        //private string key = "Q2ONoncZ5S57UVWeu04zuW5WZh"; // TODO: generate your own random string
        private string clientId = "d44646bcbd2e4b95a88ee5d598668b2e"; // TODO: use your clientId
        private string clientSecret = "0a5642b0fcd34b5ba9640e06db7e21fd"; // TODO: use your API-key
        public IActionResult Index() {
            // this is just to make sure a session cookie is created in the example app
            HttpContext.Session.Set("dummy", Encoding.ASCII.GetBytes("dummy-value"));
            return View();
        }

        private static string Encode(string input, byte[] key) {
            HMACSHA256 hmacSHA256 = new HMACSHA256(key);
            byte[] inputArray = Encoding.ASCII.GetBytes(input);
            MemoryStream inputStream = new MemoryStream(inputArray);
            return hmacSHA256.ComputeHash(inputStream).Aggregate("", (s, e) => s + String.Format("{0:x2}", e), s => s);
        }

        private static string ClaimValue(IEnumerable<Claim> claims, string key) {
            var first = claims.FirstOrDefault(c => c.Type == key);
            if (first == null) {
                return "";
            }
            return first.Value;
        }

        [HttpGet("/home/callback")]
        public async Task<IActionResult> CallbackAsync(string code, string state) {
            var sessionId = HttpContext.Session.Id;
            // get salt from state
            //var stateParts = state.Split('.');
            //if (stateParts.Length != 2)
            //{
            //    // TODO: you probably want to show your own error screen here
            //    // something is wrong with the state
            //    return View("ErrorLogin", new ErrorLoginViewModel()
            //    {
            //        Error = "Incorrect state",
            //        ErrorDescription = "Invalid state",
            //    });
            //}
            //else
            //{
            //    // all OK so far
            //    var salt = stateParts[0];
            //    var stateHmac = stateParts[1];
            //    var expectedStateHmac = Encode(sessionId + salt, Encoding.ASCII.GetBytes(key));
            //    if (stateHmac != expectedStateHmac)
            //    {
            //        // TODO: you probably want to show your own error screen here
            //        // incorrect hmac
            //        return View("ErrorLogin", new ErrorLoginViewModel()
            //        {
            //            Error = "Incorrect state",
            //            ErrorDescription = "State HMAC mismatch",
            //        });
            //    }
            //}

            var client = new HttpClient();
            client.SetBasicAuthenticationOAuth(clientId, clientSecret);
            var response = await client.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest {
                Address = hostURL + "/paymentiq/oauth/token",
                Code = code,
                //RedirectUri = string.Format("{0}://{1}{2}", Request.Scheme, Request.Host, "/callback"),
                RedirectUri = "https://2955-89-233-222-171.ngrok.io/home/callback",
            });

            // handle error
            // TODO: you probably want to show your own error screen here
            if (response.Error != null) {
                return View("ErrorLogin", new ErrorLoginViewModel() {
                    Error = response.Error,
                    ErrorDescription = response.ErrorDescription,
                });
            }

            //var identityToken = new JwtSecurityTokenHandler().ReadJwtToken(response.IdentityToken);
            
            if (response.HttpStatusCode == System.Net.HttpStatusCode.OK) {
                var loggedIn = JsonConvert.DeserializeObject<BankIdLoggedInModel>(response.Raw);
                return View("User", loggedIn);
            }
            return Error();

            //var claims = identityToken.Claims;
            //// extract claims
            //var loggedInModel = new LoggedInModel() {
            //    Name = ClaimValue(claims, "name"),
            //    FamilyName = ClaimValue(claims, "family_name"),
            //    GivenName = ClaimValue(claims, "given_name"),
            //    Gender = ClaimValue(claims, "gender"),
            //    Birthdate = ClaimValue(claims, "birthdate"),
            //    SSN = ClaimValue(claims, "ssn"),
            //    SignID = ClaimValue(claims, "sign_id"),
            //    Nonce = ClaimValue(claims, "nonce"),
            //};
            { // validate nonce
              //var nonceParts = loggedInModel.Nonce.Split('.');
              //if (nonceParts.Length != 2)
              //{
              //    // incorrect nonce
              //    // TODO: you probably want to show your own error screen here
              //    return View("ErrorLogin", new ErrorLoginViewModel()
              //    {
              //        Error = "Incorrect nonce",
              //        ErrorDescription = "Nonce got wrong format",
              //    });
              //}
              //else
              //{
              //    // ok so far
              //    var salt = nonceParts[0];
              //    var nonceHmac = nonceParts[1];
              //    var expectedNonceHmac = Encode(salt + sessionId, Encoding.ASCII.GetBytes(key));
              //    if (nonceHmac != expectedNonceHmac)
              //    {
              //        // TODO: you probably want to show your own error screen here
              //        return View("ErrorLogin", new ErrorLoginViewModel()
              //        {
              //            Error = "Incorrect nonce",
              //            ErrorDescription = "Nonce HMAC mitmatch",
              //        });
              //    }
              //}
            }

            //if (loggedInModel.SSN != null && loggedInModel.SSN.Length > 8)
            //{
            //    // create masked SSN
            //    loggedInModel.SSNMask = loggedInModel.SSN.Substring(0, 8) + "****";
            //}

            // show User-view if everything is OK
            // TODO: you probably want to show something else (e.g. welcome screen)
            
        }

        [HttpGet]
        public IActionResult Auth() {
            // redirect user to login
            // use hmac's to validate auth is initiated by us
            var sessionId = HttpContext.Session.Id;
            var salt = Guid.NewGuid().ToString();
            var stateHmac = Encode(sessionId + salt, Encoding.ASCII.GetBytes(key));
            var nonceHmac = Encode(salt + sessionId, Encoding.ASCII.GetBytes(key));
            var state = salt + "." + stateHmac;
            var nonce = salt + "." + nonceHmac;

            var appURL = string.Format("{0}://{1}", Request.Scheme, Request.Host);

            //"https://test-api.paymentiq.io/paymentiq/oauth/authorize?client_id=d44646bcbd2e4b95a88ee5d598668b2e&redirect_uri=http://localhost:53163/signin-paymentiq?stateKey=ip0M1dFCvpbtm-70Erxd6y-fuRA0Ms4ThEiJ_bDtJF4f0jCvoypXVWNBzYcoYIc1fObor2876ZMB3WQgtjihcSySlWCHQ5tvW3-CdmOu6xJpbpk3mqme5is8wj3zg7ZToMRSbqoDsCQJR3APXrjtcYe93WUFWFW1aNu-sZzOiw2ihQJ1asI6TYqW36y_DDN8WBF4mGkD7M8GSn7crQ_y-7j8f6sZuEbzN4BbSXmCQFdjO9y-p5oB5CqmgbXgufXX2oPbVFnEmsXHaI9sdJpGz_CCd_47g68-GSWUFTIkl-GFHCrBmN1zdD94Wr6AIJFlzIlvGh0FZvJk_QT3e4gwI9EQFsuzUEIRxhA8g99B_WoS1ISQcTgJ-jettogBpkk3C8nbuCQwBVeqSE7Ft1Z9yq18tzkEzDMldLCYoCu1LaOXLG7QUVokY1KXuIw3HpmnUJfi_Q&identity_provider=gii-bankid-se&ssn=198407070294&display=popup&ui_friendly=bokase-1&provider_attributes[bankid-se-device]=other&provider_attributes[bankid-se-qr]=false&provider_attributes[ui_locales]=sv&provider_attributes[platform]="
            // construct total URL
            var url = string.Format("{0}/paymentiq/oauth/authorize?client_id={1}" +
                "&redirect_uri={2}" +
                "&identity_provider=gii-bankid-se" +
                "&ssn={3}" +
                "&display=popup" +
                "&ui_friendly=true" +
                "&provider_attributes[bankid-se-device]=other" +
                "&provider_attributes[bankid-se-qr]=false" +
                "&provider_attributes[ui_locales]=sv" +
                "&provider_attributes[platform]=",
            hostURL,
            clientId,
            Uri.EscapeDataString("https://2955-89-233-222-171.ngrok.io/home/callback?stateKey=" + state),
            "198407070294");
            return Redirect(url);



            //  + "/signin-paymentiq

            //var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            //    {"client_id", clientId},
            //    {"redirect_uri", redirectUri}, // Redirect handled inside InvokeReplyPathAsync()
            //    {"identity_provider", Options.IdentityProvider.Name},
            //    {"ssn", pin},
            //    {"display", "popup"}, // page customized for iframe
            //    {"ui_friendly", "bokase-1"}, // Boka theme
            //    {"provider_attributes[bankid-se-device]", string.IsNullOrEmpty(pin) ? "same" : "other"},
            //    {"provider_attributes[bankid-se-qr]", "false"},
            //    {"provider_attributes[ui_locales]", Request.Query["locale"]},
            //    {"provider_attributes[platform]", string.IsNullOrWhiteSpace(pin) && !string.IsNullOrWhiteSpace(isMobile) && bool.Parse(isMobile) ? "native" : ""} // open BankID app automatically on same device
            //};
        }

        [HttpGet("Home/Sign")]
        public async Task<IActionResult> SignAsync() {
            // create sign-post
            // TODO: you want to sign something else
            var visibleText = "Visible text to sign.";
            // TODO: you want to sign some other hidden text (optional)
            var hiddenText = "some file-hash";

            var client = new HttpClient();
            client.SetBasicAuthenticationOAuth(clientId, clientSecret);
            var signContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("visisible_text", visibleText),
                new KeyValuePair<string, string>("hidden_text", hiddenText),
            });
            var request = new HttpRequestMessage() {
                Method = HttpMethod.Post,
                RequestUri = new Uri(hostURL + "/api/oauth/sign"),
                Content = signContent,
            };
            var response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode) {
                // TODO: you should handle error here
                Console.WriteLine("Error");
            }
            // deserialize response
            var signPostDefinition = new { id = "" };
            var contentString = await response.Content.ReadAsStringAsync();
            var signPost = JsonConvert.DeserializeAnonymousType(contentString, signPostDefinition);

            // redirect user to sign
            // use hmac's to validate auth is initiated by us
            var sessionId = HttpContext.Session.Id;
            var salt = Guid.NewGuid().ToString();
            var stateHmac = Encode(sessionId + salt, Encoding.ASCII.GetBytes(key));
            var nonceHmac = Encode(salt + sessionId, Encoding.ASCII.GetBytes(key));
            var state = salt + "." + stateHmac;
            var nonce = salt + "." + nonceHmac;

            var appURL = string.Format("{0}://{1}", Request.Scheme, Request.Host);

            // construct total URL
            var url = string.Format("{0}/api/oauth/auth?client_id={1}&redirect_uri={2}&response_type=code&scope=openid&state={3}&nonce={4}&sign_id={5}",
            hostURL,
            clientId,
            Uri.EscapeDataString(appURL + "/callback"),
            state,
            nonce,
            signPost.id);
            return Redirect(url);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error() {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
