using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ProtonMail.Srp;

namespace SrpExample
{
    class Program
    {
        static void Main(string[] args)
        {
            string username = "jakubqa";
            string password = "abc123";
            string salt = "yKlc5/CvObfoiw==";
            string signedModulus = 
                "-----BEGIN PGP SIGNED MESSAGE-----\n" +
                "Hash: SHA256\n" +
                "\n" +
                "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\r\n" +
                "-----BEGIN PGP SIGNATURE-----\n" +
                "Version: ProtonMail\n" +
                "Comment: https://protonmail.com\n" +
                "\n" +
                "wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\n" +
                "GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\n" +
                "kvNM7qIK\n" +
                "=q6vu\n" +
                "-----END PGP SIGNATURE-----";

            string serverEphemeral = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";

            Srp.GoProofs oStr = Srp.GenerateProofs(4, username, password, salt, signedModulus, serverEphemeral);
            Console.WriteLine(oStr);
        }
    }
}
