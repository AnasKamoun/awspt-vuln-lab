using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;

// Intentionally vulnerable lab for SAST validation. DO NOT deploy.
namespace VulnLab
{
    public static class Vuln
    {
        // Hardcoded fake secrets (realistic shapes) — CWE-798: Use of Hard-coded Credentials
        private const string ConnString =
            "Server=db.internal;Database=app;User Id=sa;Password=Sup3rS3cr3t!2024;";
        private const string AwsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        private const string ApiToken = "sk_live_4eC39HqLyjWDarjtT1zdp7dcAbCdEfGh1234";

        // CWE-89: SQL Injection
        public static void SqlInjection(HttpRequest Request)
        {
            string id = Request.Query["id"];
            using (var conn = new SqlConnection(ConnString))
            {
                var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id, conn);
                conn.Open();
                cmd.ExecuteReader();
            }
        }

        // CWE-78: OS Command Injection
        public static void CommandInjection(HttpRequest Request)
        {
            string c = Request.Query["c"];
            Process.Start("cmd.exe", "/c " + c);
        }

        // CWE-502: Deserialization of Untrusted Data
        public static object UnsafeDeserialize(HttpRequest Request)
        {
            byte[] blob = Convert.FromBase64String(Request.Form["payload"]);
            using (var stream = new MemoryStream(blob))
            {
                var fmt = new BinaryFormatter();
                return fmt.Deserialize(stream);
            }
        }

        // CWE-611: XML External Entity (XXE) Injection
        public static void XxeParse(HttpRequest Request)
        {
            string xml = Request.Form["xml"];
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver(); // external entities enabled
            doc.LoadXml(xml);
        }

        // CWE-327: Use of a Broken Cryptographic Algorithm (MD5)
        public static string WeakHash(HttpRequest Request)
        {
            string pwd = Request.Form["password"];
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(pwd));
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        // CWE-330: Use of Insufficiently Random Values for a security token
        public static string WeakToken(HttpRequest Request)
        {
            string seed = Request.Query["seed"];
            var rng = new Random(seed.GetHashCode());
            return rng.Next().ToString("X8");
        }

        // CWE-79: Reflected Cross-Site Scripting (XSS)
        public static void ReflectedXss(HttpRequest Request, HttpResponse Response)
        {
            string x = Request.Query["x"];
            Response.Write("<div>Hello " + x + "</div>");
        }

        // CWE-22: Path Traversal
        public static string PathTraversal(HttpRequest Request)
        {
            string file = Request.Query["file"];
            return File.ReadAllText("C:\\app\\data\\" + file);
        }

        // CWE-918: Server-Side Request Forgery (SSRF)
        public static string Ssrf(HttpRequest Request)
        {
            string url = Request.Query["url"];
            using (var client = new WebClient())
            {
                return client.DownloadString(url);
            }
        }

        // CWE-601: Open Redirect
        public static void OpenRedirect(HttpRequest Request, HttpResponse Response)
        {
            string next = Request.Query["next"];
            Response.Redirect(next);
        }

        // CWE-90: LDAP Injection
        public static void LdapInjection(HttpRequest Request)
        {
            string user = Request.Query["user"];
            var entry = new System.DirectoryServices.DirectoryEntry("LDAP://corp");
            var search = new System.DirectoryServices.DirectorySearcher(entry);
            search.Filter = "(uid=" + user + ")";
            search.FindOne();
        }

        // CWE-94: Code Injection via dynamic file write of attacker-controlled config
        public static void WriteAttackerFile(HttpRequest Request)
        {
            string name = Request.Query["name"];
            string body = Request.Form["body"];
            File.WriteAllText("C:\\app\\uploads\\" + name, body);
        }

        // CWE-117: Log Injection / improper neutralization in log output
        public static void LogInjection(HttpRequest Request)
        {
            string ua = Request.Headers["User-Agent"];
            File.AppendAllText("C:\\app\\logs\\access.log", "visit: " + ua + "\n");
        }

        // CWE-89: Second SQLi sink fed from CLI args / env (taint from process input)
        public static void SqlFromCliArgs(string[] args)
        {
            string name = args.Length > 0 ? args[0] : Environment.GetEnvironmentVariable("USER_NAME");
            using (var conn = new SqlConnection(ConnString))
            {
                var cmd = new SqlCommand("SELECT * FROM Accounts WHERE Name = '" + name + "'", conn);
                conn.Open();
                cmd.ExecuteNonQuery();
            }
        }

        // CWE-78: Command sink fed from stdin
        public static void CommandFromStdin()
        {
            string line = Console.ReadLine();
            Process.Start("/bin/sh", "-c \"" + line + "\"");
        }
    }
}
