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
using LoginSystem_client;

namespace LoginSystem_client
{
    internal class Program
    {
        static string trusted_public_key = "<RSAKeyValue><Modulus>6Tp6hQV1fDSY1+5S9OwgyWZauDY/0NT1lQBktp+9axbDYDZG1hBYb+t2p/qceLGAMSY1VYrZX6TL1Ob1xRbEAgsw23DDKDlOKlK9TxjxJNId/F8fb8ZWjRQgjxnlsPNu+pyTxeg00hl5UPCj+ed81j1MDxirianm8q61MFBtYOE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        static TLS_library tls_lib = new TLS_library();
        static byte[] symm_key = tls_lib.GetSymmetricKey();
        static bool handshake_done = false;

        static public string ips;

        static public string last_msg = "";
        static Random rand = new Random();
        static int connection_id = rand.Next();
        static int listening_port = rand.Next() % 30000 + 3000;

        static string binded_code = @"C:\binding.cs";

        static string url = "http://unyxe.mywire.org:8080";


        public static void Main()
        {
            //GetUsernameByIP("");
            //Console.ReadLine();




            TLSHandShake();

            //Ping();

            Console.WriteLine();
            while (true)
            {
                try
                {
                    Console.Write("[Request] ");
                    string message = Console.ReadLine();
                    if (message.StartsWith("<root>\\bind_code\\?"))
                    {
                        SendCodeBinding(binded_code, message);
                        continue;
                    }
                    Send(message, 10);
                }
                catch (DivideByZeroException) { }
            }

        }
        public static void SendCodeBinding(string src_path, string req)
        {
            //Console.WriteLine("Sending");
            string code = File.ReadAllText(src_path);
            Console.WriteLine(code);
            Send(req + "&src-" + ToBase64(code), 10);
            //Console.WriteLine("Sent");
        }

        /*
        try
        {
            TLS_library lib = new TLS_library();
            byte[] symm_key = lib.GetSymmetricKey();
            string pub_key = FromBase64(body);
            //Console.WriteLine(pub_key);
            string symm_key_enc = ToBase64FromByte(lib.EncryptAssymetric(symm_key, pub_key));
            active_connection_ids.Add(connection_id);
            ip_addreses.Add(client.Client.RemoteEndPoint.ToString());
            tls_libs.Add(lib);
            Send(stream, -1, symm_key_enc);
        }
        catch { Send(stream, -1, "Encryption failed"); }
        */
        public static void TLSHandShake()
        {
            Console.WriteLine("[TLS handshake] Started...");
            Send("Client hello!", 10);
            if(last_msg.StartsWith("Server hello! "))
            {
                string server_public_key = FromBase64(last_msg.Substring(14));
                //Console.WriteLine(server_public_key);
                if(server_public_key != trusted_public_key)
                {
                    Console.WriteLine("Public key is not trusted! Continue?");
                    if(Console.ReadLine() == "Y")
                    {

                    }
                    else
                    {
                        while (true) { Console.WriteLine("Close an application now. "); Console.ReadLine(); }
                    }
                }
                Send("Key! " + ToBase64FromByte(tls_lib.EncryptAssymetric(Encoding.ASCII.GetBytes(ToBase64FromByte(symm_key)), server_public_key)), 10);
                string finish_response = tls_lib.DecryptSymmetric(last_msg, symm_key);
                if (finish_response.StartsWith("Finish!"))
                {
                    handshake_done = true;
                    Console.WriteLine("[TLS handshake] Success!");
                }
                else
                {
                    Console.WriteLine("Weird finish: " + finish_response);
                }
            }
            else
            {
                Console.WriteLine("Weird: " + last_msg);
            }
            //Console.WriteLine(ToBase64FromByte(symm_key));
            
        }
        public static void Send(string str, int timeout)
        {
            string d = str;
            string sent = ToBase64(str);
            if (handshake_done)
            {
                sent = tls_lib.EncryptSymmetric(sent, symm_key);
            }
            SendHttp(sent, timeout, d);
        }
        public static void Ping()
        {
            while (true)
            {
                Send(@"<root>\log\", 1);
            }

        }
        public static void SendHttp(string str, int timeout, string display_str)
        {
            //Console.WriteLine("[DEBUG] " + str);
            HttpContent content = new StringContent(str + "~");

            HttpClient client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(timeout);
            client.DefaultRequestHeaders.Add("Connection_id", connection_id + "");
            DateTime now = DateTime.Now;
            HttpResponseMessage response;
            try
            {
                response = client.PostAsync(url, content).Result;
            }
            catch { Console.WriteLine("[Response] Failed to send, retry..."); SendHttp(str, timeout, display_str); return; }
            byte[] responseData = response.Content.ReadAsByteArrayAsync().Result;
            TimeSpan diff = DateTime.Now.Subtract(now);
            last_msg = Encoding.ASCII.GetString(responseData);
            if (last_msg.StartsWith("Encryption failed"))
            {
                handshake_done = false;
                Console.WriteLine("[TLS handshake] Key change...");
                TLSHandShake();
                Console.WriteLine("[TLS handshake] Key change finished!");


                Console.WriteLine("[Request] " + display_str);
                Send(display_str, timeout);
                return;
            }
            if (handshake_done)
            {
                last_msg = tls_lib.DecryptSymmetric(last_msg, symm_key);
                Console.Write("[Response] ");
                Console.WriteLine(last_msg);
                Console.Write("    Latency: " + diff.TotalMilliseconds + "ms \n");
            }
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