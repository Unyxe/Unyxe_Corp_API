using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using System.IO;

namespace LoginSystem_server
{
    internal class Program
    {
        static Socket socket;
        static IPAddress ip_addr;
        static IPEndPoint endPoint;
        static public string ips;


        static IPAddress ip2;
        static IPEndPoint endPoint2;
        static Thread listenThread;


        static int opp_dec;
        static public string last_msg = "";
        static Random rand = new Random();
        static int listening_port = rand.Next() % 30000 + 3000;

        static string binded_code = @"L:\binding.cs";

        public static HttpClient http_client = new HttpClient()
        {
            //BaseAddress = new Uri("http://unyxe.mywire.org"),
            BaseAddress = new Uri("http://" + GetLocalIPAddress() + ":8080"),
        };


        public static void Main()
        {

            //GetUsernameByIP("");
            //Console.ReadLine();
            string s = "";


            

            while (true)
            {
                try
                {
                    string message = Console.ReadLine();
                    if (message.StartsWith("<root>\\bind_code\\?"))
                    {
                        SendCodeBinding(binded_code, message);
                        continue;
                    }
                    Send(message + "~" + listening_port);
                }
                catch { }
            }

        }
        public static void SendCodeBinding(string src_path, string req)
        {
            //Console.WriteLine("Sending");
            string code = File.ReadAllText(src_path);
            Console.WriteLine(code);
            Send(req +ToBase64(code)+ "~" + listening_port);
            //Console.WriteLine("Sent");
        }
        public static void Send(string str)
        {
            SendHttp(ToBase64(str));
        }
        public static void SendHttp(string str)
        {
            HttpResponseMessage response = http_client.GetAsync(str).GetAwaiter().GetResult();
            string g = response.Headers.Pragma.ToString();
            var l = response.Headers.ToList();
            last_msg = FromBase64(l[0].Value.First());

            Console.WriteLine(last_msg);
            Console.WriteLine("___________________________________");
        }
        public static void SendToServer(string str)
        {
            Send(str + "~" + listening_port);
        }
        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return "255.255.255.255";
        }

        public static string ToBase64(string input)
        {
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(input));
        }

        public static string ToBase64FromByte(byte[] input)
        {
            return Convert.ToBase64String(input);
        }
        public static byte[] FromBase64ToByte(string input)
        {
            return Convert.FromBase64String(input);
        }

        public static string FromBase64(string input)
        {
            return Encoding.Default.GetString(Convert.FromBase64String(input));
        }
    }
}
