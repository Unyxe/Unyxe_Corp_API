using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Text.Json.Nodes;
using Unyxe_Corp_API;
using System.Net.Http;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Runtime.InteropServices;
using System.Reflection;

namespace Unyxe_corp_API
{
    internal class Program
    {
        static IPAddress ipAddress = IPAddress.Any;
        static int port = 8080;
        static int port_tunnels = 8090;
        static int port_request_tunnels = 8091;
        static TcpListener listener_main = new TcpListener(ipAddress, port);
        static TcpListener listener_tunnels = new TcpListener(ipAddress, port_tunnels);
        static TcpListener listener_request_tunnels = new TcpListener(ipAddress, port_request_tunnels);


        static public string last_msg = "";


        static bool http_display_mode = false;
        static bool robust_enable = false;

        static Random rand = new Random();

        static string pre_http = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: ";

        static TLS_library main_tls_lib = new TLS_library();
        static string server_public_key = "<RSAKeyValue><Modulus>6Tp6hQV1fDSY1+5S9OwgyWZauDY/0NT1lQBktp+9axbDYDZG1hBYb+t2p/qceLGAMSY1VYrZX6TL1Ob1xRbEAgsw23DDKDlOKlK9TxjxJNId/F8fb8ZWjRQgjxnlsPNu+pyTxeg00hl5UPCj+ed81j1MDxirianm8q61MFBtYOE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        static string server_private_key = "<RSAKeyValue><Modulus>6Tp6hQV1fDSY1+5S9OwgyWZauDY/0NT1lQBktp+9axbDYDZG1hBYb+t2p/qceLGAMSY1VYrZX6TL1Ob1xRbEAgsw23DDKDlOKlK9TxjxJNId/F8fb8ZWjRQgjxnlsPNu+pyTxeg00hl5UPCj+ed81j1MDxirianm8q61MFBtYOE=</Modulus><Exponent>AQAB</Exponent><P>+5JIGhs+5mDnTcHPZO/QeXFTNJM9syxE4Nnj//iV815w0TrYgAox+oxyOySy6pWa7xSSHWOkjqu+lFL9va+6Bw==</P><Q>7VWIj6+Wq/UxyhGf7upFGLjEKFofjRFVdFgL1bsOf7fPXQWX/TOc1p3sStiqBRWBkaDWsG9iOcGZ6uioHsFz1w==</Q><DP>NZVPxDe/awSC394DFaW6ytMnfNBL2Qj51sayOIgzMDYSY45cJNGHGa2mexBzB2I8MOY5xQa/OyA7pI4Uu71dKw==</DP><DQ>VZK3kIdRHmNkNmWwcuaJT2afY6VLJwQO+codSk0N50MRQ4sWyDbp4ABFCJ+iff7JHwcNIcSneAe0RZzpsV0zNQ==</DQ><InverseQ>IIclu8r2E51bVeCJhqpevCXdPRmEh5AZK4eZcoArM6AK580ajw5S5J3uad8J5Y1Qqf/Hm04axp4DHnB9PRs9mQ==</InverseQ><D>3PRR7oPlce5Cfw+B+BdcWHFnsO10N9wJbUgaIgnj4fiG0DeblGGX5zAkEbATXSSMVgPks03/8eSmVuUYIcgXmCjjGhq2V1dn3Kr7tst5tTDZVzRlS7dPG2pXlvt8jutpI/YxbNMRgUKXyIHRpxQA1P4dmx19UUFbev9PHiQT4iE=</D></RSAKeyValue>";

        //TLS handshake params
        static List<int> active_connection_ids = new List<int>();
        static List<string> ip_addreses = new List<string>();
        static List<byte[]> symm_keys = new List<byte[]>();


        //Bard API keys
        public static string[] bard_api_keys = new string[1] { "VwjYyK2Kr3VynTgxVkbPEuT6jOiUbyeKnboKHr2vCpiYXBSIbT70XWlQJAR9sPbYUDExpQ." };
        public static string[] bard_at_vars = new string[1] { "ABi_lZjZ6Ym_9M-LrT9Rhfwlr2rr:1682883560998" };
        public static int bard_api_key_num = 0;

        //Svn tunnels
        public static List<TcpClient> svn_tunnels_clients = new List<TcpClient>();
        public static List<NetworkStream> svn_tunnels_streams = new List<NetworkStream>();
        public static List<string> svn_tunnel_ids = new List<string>();

        //ChatApp vars
        public static List<TcpClient> chatapp_tunnels_clients = new List<TcpClient>();
        public static List<NetworkStream> chatapp_tunnels_streams = new List<NetworkStream>();
        public static List<string> chatapp_tunnel_ids = new List<string>();
        public static List<string> chatapp_tunnel_auths = new List<string>();
        public static List<string> chatapp_channel_ids = new List<string>();
        public static List<string> chatapp_channel_names = new List<string>();
        public static List<List<string>> chatapp_channels_members_auths = new List<List<string>>();
        public static List<string[]> messages_queue = new List<string[]>();


        static string home_dir = Directory.Exists(@"D:\UnyxeCorpAPI\") ? @"D:\UnyxeCorpAPI\" : @"L:\UnyxeCorpAPI\";

        static string databases_dir = home_dir + @"Databases\";
        static string binded_functions_dir = home_dir + @"BindedFunctions\";
        static string binded_functions_src_dir = home_dir + @"BindedFunctionsSrc\";

        static string[][] root_users =
        {
            new string[] { "admin", "admin", "Admin" },
            new string[] { "Timur", "secret123", "User" },
        };
        static string[][] root_auth_tokens =
        {
            new string[] { "admin", "c90010128ac4159bd196b5bb5d1a99dc" },
            new string[] { "Timur", "0ad525712b9c429a7205304c591f3cf5" },
        };


        static string[] apps = { "root", "chores", "bard_search", "svntunnel", "chatapp" };
        static string[][] database_names =
        {
            new string[] {"users", "auth_tokens", "apps", "database_names", "database_paths", "roles", "methods","method_bindings", "method_acls", "column_names", "default_values"},
            new string[] {"users", "auth_tokens", "chores"},
            new string[] {"users", "auth_tokens"},
            new string[] {"users", "auth_tokens"},
            new string[] {"users", "auth_tokens"},
        };
        static string[][] database_paths =
        {
            new string[] {@"root\us.db", @"root\au.db", @"root\apps.db", @"root\dbnames.db",@"root\dbpaths.db",@"root\roles.db",@"root\methods.db", @"root\method_bindings.db",@"root\method_acls.db",@"root\column_names.db",@"root\def_vals.db",},
            new string[] {@"ChoresAPP\us.db", @"ChoresAPP\au.db", @"ChoresAPP\ch.db"},
            new string[] {@"bard_search\us.db", @"bard_search\au.db"},
            new string[] {@"svn_tunnel\us.db", @"svn_tunnel\au.db"},
            new string[] {@"chatapp\us.db", @"chatapp\au.db"},
        };
        static string[][] roles =
        {
            new string[] { "Admin", "User", "Anonymous" },
            new string[] { "Admin", "User", "Anonymous" },
            new string[] { "Admin", "User", "Anonymous" },
            new string[] { "Admin", "User", "Anonymous" },
            new string[] { "Admin", "User", "Anonymous" },
        };
        static string[][][] column_names =
        {
            //root
            new string[][]
            {
                new string[] { "username", "password", "role"},
                new string[] { "username", "auth_token"},
                new string[] { "null"},
                new string[] { "null"},
                new string[] { "null"},
                new string[] { "null"},
                new string[] { "null"},
                new string[] { "null"},
                new string[] { "null"},
                new string[] { "null"},
                new string[] { "null"},
            },
            //APP: chores
            new string[][]
            {
                new string[] { "username", "password", "role"},
                new string[] { "username", "auth_token"},
                new string[] { "username_sender", "username_reciever", "chore_type", "chore_desc", "done_it"},
            },
            //APP: bard_search
            new string[][]
            {
                new string[] { "username", "password", "role", "credit"},
                new string[] { "username", "auth_token"},
            },
            //APP: SVN Tunnel
            new string[][]
            {
                new string[] { "username", "password", "role"},
                new string[] { "username", "auth_token"},
            },
            //APP: Chat App
            new string[][]
            {
                new string[] { "username", "password", "role"},
                new string[] { "username", "auth_token"},
            },

        };
        static string[][][] default_values =
        {
            //root
            new string[][]
            {
                new string[] { "null", "null", "Admin" },
                new string[] { "null", "null" },
                new string[] { "" },
                new string[] { "" },
                new string[] { "" },
                new string[] { "" },
                new string[] { "" },
                new string[] { "" },
                new string[] { "" },
                new string[] { "" },
            },
            //APP: chores
            new string[][]
            {
                new string[] { "null", "null", "User"},
                new string[] { "null", "null"},
                new string[] { "null", "null", "null", "-", "false"},
            },
            //APP: bard_search
            new string[][]
            {
                new string[] { "null", "null", "User", "100"},
                new string[] { "null", "null"},
            },
            //APP: svn_tunnel
            new string[][]
            {
                new string[] { "null", "null"},
                new string[] { "null", "null"},
            },
            //APP: ChatApp
            new string[][]
            {
                new string[] { "null", "null"},
                new string[] { "null", "null"},
            },
        };
        static string[][] available_methods =
        {
            new string[] { "sign", "log", "bind_code","list_ram_dbs","new_app", "delete_app", "new_db", "delete_db", "new_method", "delete_method"},
            new string[] { "sign", "log", "new_chore"},
            new string[] { "sign", "log", "search"},
            new string[] { "req", "open_tunnel"},
            new string[] { "sign", "log", "auth_tunnel","msg", "create_channel", "join_channel"},
        };
        static string[][] method_bindings =
        {
            new string[] { "hardcoded", "hardcoded", "hardcoded", "hardcoded", "hardcoded", "hardcoded", "hardcoded", "hardcoded", "hardcoded", "hardcoded"},
            new string[] { "hardcoded", "hardcoded", "hardcoded"},
            new string[] { "hardcoded", "hardcoded", "hardcoded"},
            new string[] { "hardcoded","hardcoded", },
            new string[] { "hardcoded","hardcoded", "hardcoded", "hardcoded", "hardcoded", "hardcoded"},
        };
        static string[][] method_permissions =
        {
            new string[]{ "0", "0:2", "0","0", "0", "0", "0", "0", "0", "0"},
            new string[]{ "0:2", "0:2", "0:1"  },
            new string[]{ "0:2", "0:2", "0:1:2"  },
            new string[]{ "0:1:2", "0:1:2"  },
            new string[]{ "0:2", "0:2", "0:1", "0:1", "0:1", "0:1"  },
        };

        static List<string[]>[][] databases;



        public static void Main()
        {
            Console.WriteLine(SvnOpenTunnel("facebook.com", 443));
            Console.WriteLine(Encoding.ASCII.GetString(main_tls_lib.DecryptAssymetric(main_tls_lib.EncryptAssymetric(Encoding.ASCII.GetBytes("Key checking..."), server_public_key), server_private_key)));
            WriteRootDatabase();
            //Console.ReadLine();

            ReadRootDatabase();
            //WriteRootDatabase();
            //Console.ReadLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\t\tUnyxe Corporation API\n\n");
            Console.WriteLine("Database initialization...");
            InitRAMDatabases();
            Console.WriteLine("Done!\n");
            Console.WriteLine("Database reading...");
            ReadDataFromDatabase();
            WriteDataToDatabase();
            Console.WriteLine("Done!\n");
            Console.WriteLine("Database structure displayment...");
            DisplayRAMDatabaseStructure();
            Console.WriteLine("Done\n");
            Console.WriteLine("Listening started!\n\n");
            Console.WriteLine(GetLocalIPAddress());
            listener_main.Start();
            listener_tunnels.Start();
            listener_request_tunnels.Start();
            ChatAppMainframe();
            Listen1();
            bool to_sh = false;
            while (true)
            {
               
                switch (Console.ReadLine())
                {
                    case "clear":
                        Console.Clear();
                        break;
                    case "shutdown":
                        to_sh = true;
                        break;
                }
                if (to_sh)
                {
                    break;
                }
            }
        }



        private static void Send_(string str, Socket clientSocket)
        {
            try
            {
                string string_http = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 25\r\nBODY_tw: " + ToBase64(str) + "\r\n\r\nHello, thats my webserver";

                byte[] buffer = Encoding.ASCII.GetBytes(string_http);
                clientSocket.Send(buffer);
                clientSocket.Close();
                if (http_display_mode)
                {
                    Console.WriteLine("[<=]" + string_http);
                }
                Console.WriteLine("|"+str + "|\n\n\n");
            }
            catch (Exception ex) when (robust_enable)
            {
                Console.WriteLine("Sending error: " + ex.Message);
                Console.WriteLine("IP is offline");
            }
            
        }
        static void Send(NetworkStream stream, int connection_id, string msg_str = null, byte[] msg_bytes = null)
        {
            if(msg_str == null && msg_bytes == null) { return; }
            string act_msg = msg_str;
            
            if(msg_bytes != null)
            {
                act_msg = ToBase64FromByte(msg_bytes);
            }
            
            string display_message = act_msg.Substring(0, act_msg.Length < 200?act_msg.Length:199);
            if (connection_id != -1)
            {
                byte[] symm_key = symm_keys[GetConnectionInd(connection_id)];
                act_msg = main_tls_lib.EncryptSymmetric(act_msg, symm_key);
            }
            string msg = pre_http + act_msg.Length + "\r\n\r\n" + act_msg;

            byte[] message = Encoding.ASCII.GetBytes(msg);
            stream.Write(message, 0, message.Length);
            int con_id = GetConnectionInd(connection_id);
            if(con_id == -1) { return;}
            Console.WriteLine("["+DateTime.Now+"][" + ip_addreses[con_id] +" <=] "+display_message + "\n");
        }

        private static void Listen1()
        {
            Thread listenThread = new Thread(new ThreadStart(ListenMain));
            listenThread.Start();
            //Thread listen_tunnelsThread = new Thread(new ThreadStart(ListenTunnels));
            //listen_tunnelsThread.Start();
            Thread listen_request_tunnelsThread = new Thread(new ThreadStart(ListenReqTunnels));
            listen_request_tunnelsThread.Start();
        }

        static async void ListenMain()
        {
            while (true)
            {
                TcpClient client = await listener_main.AcceptTcpClientAsync();
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
                Task.Run(() => { Listen_(client); });
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
            }
        }
        static async void ListenTunnels()
        {
            while (true)
            {
                TcpClient client = await listener_tunnels.AcceptTcpClientAsync();
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
                Task.Run(() => { ListenTunnels_(client); });
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
            }
        }
        static async void ListenReqTunnels()
        {
            while (true)
            {
                TcpClient client = await listener_request_tunnels.AcceptTcpClientAsync();
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
                Task.Run(() => { ListenReqTunnel_(client); });
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
            }
        }
        private static byte[] ReadNetworkStream(NetworkStream m_stream)
        {
            //Console.WriteLine("Reading stream");
            List<byte> m_buffer = new List<byte>();
            while (true)
            {
                var next = m_stream.ReadByte();
                string b = Encoding.ASCII.GetString(new byte[] { (Byte)next });
                if (next < 0 || next == 126) {break; } // no more data

                m_buffer.Add((byte)next);
            }
            //Console.WriteLine("Read finished");
            return m_buffer.ToArray();
        }
        static void ListenTunnels_(TcpClient client)
        {
            NetworkStream stream = client.GetStream();
            NetworkStream target = null;
            string tunnel_id_str = "";
            while (true)
            {
                var next = stream.ReadByte();
                if (next == -1){ break;}
                string t = Encoding.ASCII.GetString(new byte[] { (byte)next });
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(t);
                if (tunnel_id_str.Length < 10) 
                { 
                    tunnel_id_str += t; 
                    if (tunnel_id_str.Length == 10) 
                    { 
                        try 
                        { 
                            tunnel_id_str = Int32.Parse(tunnel_id_str) + ""; 
                            /*Console.WriteLine("Tunnel ID identified: " + tunnel_id_str);*/ 
                        } catch { return; } 
                        int tunnel_ind = SVNGetTunnelIndById(tunnel_id_str);
                        if(tunnel_ind == -1) { return; }
                        target = svn_tunnels_streams[tunnel_ind];

                        Thread br = new Thread(() =>
                        {
                            while (true)
                            {
                                stream.WriteByte((byte)target.ReadByte());
                            }
                        });
                        br.Start();
                    }
                }
                else
                {
                    target.WriteByte((byte)stream.ReadByte());
                }
            }
        }

        static void ListenReqTunnel_(TcpClient client)
        {
            NetworkStream stream = client.GetStream();
            chatapp_tunnels_clients.Add(client);
            chatapp_tunnels_streams.Add(stream);
            string tunnel_id = rand.Next() + "";
            chatapp_tunnel_ids.Add(tunnel_id);
            chatapp_tunnel_auths.Add("");
            WriteBytesToNS(stream, Encoding.ASCII.GetBytes(tunnel_id));
            while (true)
            {
                if (!stream.DataAvailable) continue;
                byte[] request_bytes = GetRequestFromNS(stream);
                string str = Encoding.ASCII.GetString(request_bytes);
                Console.WriteLine(str);
            }
        }
        static void WriteBytesToNS(NetworkStream stream, byte[] bytes)
        {
            try
            {
                foreach (byte b in bytes)
                {
                    stream.WriteByte(b);
                }
                stream.WriteByte(126);
            }
            catch { return; }
        }
        static byte[] GetRequestFromNS(NetworkStream stream)
        {
            List<byte> byte_list = new List<byte>();
            while (true)
            {
                int next = stream.ReadByte();
                if (next == -1 || next == 126)
                {
                    break;
                }
                byte_list.Add((byte)next);
            }
            return byte_list.ToArray();
        }
        
        static void Listen_(TcpClient client)
        {
            //Console.WriteLine("[DEBUG] " + "New request");
            using (client)
            {
                NetworkStream stream = client.GetStream();

                string request = "";
                try
                {
                    request = Encoding.ASCII.GetString(ReadNetworkStream(stream));
                }
                catch { return; }

                // Get the content length from the headers
                int contentLength = 0;
                int connection_id = -1;
                foreach (string line in request.Split('\n'))
                {
                    if (line.StartsWith("Content-Length:"))
                    {
                        contentLength = int.Parse(line.Split(':')[1].Trim());
                    }
                    if (line.StartsWith("Connection_id:"))
                    {
                        connection_id = int.Parse(line.Split(':')[1].Trim());
                    }
                }


                if (!request.StartsWith("POST")) { return; }
                string body = request.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries)[1];
                

                //TLS handshake/decryption
                if (connection_id == -1) { return; }
                int conn_id = GetConnectionInd(connection_id);
                if (conn_id == -1)
                {
                    body = FromBase64(body);
                    //Console.WriteLine(body);
                    if (body.StartsWith("Client hello!"))
                    {
                        
                        Send(stream, -1, "Server hello! "+ToBase64(server_public_key)); 
                        return;
                    }
                    else if (body.StartsWith("Key! "))
                    {
                        try
                        {
                            string enc_key = body.Substring(5);
                            TLS_library lib = new TLS_library();
                            byte[] symm_key = FromBase64ToByte(Encoding.ASCII.GetString(main_tls_lib.DecryptAssymetric(FromBase64ToByte(enc_key), server_private_key)));
                            symm_keys.Add(symm_key);
                            active_connection_ids.Add(connection_id);
                            ip_addreses.Add(client.Client.RemoteEndPoint.ToString());
                            Send(stream, connection_id, "Finish!");
                            return;
                        }
                        catch when (robust_enable){ Send(stream, -1, "Encryption failed"); return; }
                    }
                    else
                    {
                        Send(stream, -1, "Encryption failed"); return;
                    }

                }
                else
                {
                    byte[] symm_key = symm_keys[GetConnectionInd(connection_id)];
                    body = main_tls_lib.DecryptSymmetric(body, symm_key);
                }

                string message = FromBase64(body);
                last_msg = message;
                if (http_display_mode)
                {
                    Console.WriteLine("[" + DateTime.Now + "][" + client.Client.RemoteEndPoint.ToString() + "]" + request);
                }
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[" + DateTime.Now + "][" + ip_addreses[GetConnectionInd(connection_id)] + " =>] " + message + "\n");
                Console.ForegroundColor = ConsoleColor.Green;

                try
                {
                    string[] app_parse = ParseForApp(message);
                    message = app_parse[1];
                    string app = app_parse[0];
                    if (!apps.Contains(app))
                    {
                        string method_success = "app_is_not_found";
                        Send(stream, connection_id, "Failed! Reason: " + method_success);
                    }
                    string[] args = ParseMessage(message, app);

                    string ipad = "";
                    string endp_str = client.Client.RemoteEndPoint.ToString();
                    for (int i = 0; i < endp_str.Length; i++)
                    {
                        if (endp_str[i] == ':')
                        {
                            break;
                        }
                        ipad += endp_str[i];
                    }
                    IPAddress ipaddr = IPAddress.Parse(ipad);
                    try
                    {
                        if (args[1] == "success")
                        {
                            //Send("Success! Method: " + args[2] + " Message_Body: " + args[3], endp);
                        }
                        else
                        {
                            //Send("Failed! Reason: " + args[1], endp);
                        }
                        if (args[1] == "success")
                        {
                            string success_doing_method = DoMethod(args[2], app, args[3], stream, connection_id);
                            if (success_doing_method == "success")
                            {
                                if (args[2] == "sign" || args[2] == "tweet")
                                {
                                    Send(stream, connection_id, "Success!");
                                }

                            }
                            else
                            {
                                Send(stream, connection_id, "Failed! Reason: " + success_doing_method);
                            }
                        }
                    }
                    catch (Exception e) when (robust_enable)
                    {
                        Send(stream, connection_id, "Failed! Server error occured! " + e.Message);
                    }

                    if (app == "root")
                    {
                        //Console.WriteLine("Writing root db...");
                        WriteRootDatabase();
                    }
                    WriteDataToDatabase();
                    ReadDataFromDatabase();
                    WriteDataToDatabase();
                }
                catch (Exception e) when (robust_enable)
                {
                    Console.WriteLine("Error occured, while trying to parse the message! " + e.Message);
                }

            }
            client.Close();
        }
        public static string tunnel_request_doer(string message, NetworkStream stream,int connection_id = -1)
        {

            string[] app_parse = ParseForApp(message);
            message = app_parse[1];
            string app = app_parse[0];
            if (!apps.Contains(app))
            {
                string method_success = "app_is_not_found";
                return "Failed! Reason: " + method_success;
            }
            string[] args = ParseMessage(message, app);
            try
            {
                if (args[1] == "success")
                {
                    //Send("Success! Method: " + args[2] + " Message_Body: " + args[3], endp);
                }
                else
                {
                    //Send("Failed! Reason: " + args[1], endp);
                }
                if (args[1] == "success")
                {
                    string success_doing_method = DoMethod(args[2], app, args[3], stream, connection_id);
                    return success_doing_method;
                }
            }
            catch (Exception e) when (robust_enable)
            {
                return "Failed! Server error occured! " + e.Message;
            }
            return null;
        }
        public static string DoMethod(string method, string app, string arguments_raw, NetworkStream stream, int connection_id)
        {

            List<string> arg_names = new List<string>();
            List<string> arg_values = new List<string>();

            string method_success = "success";
            if (arguments_raw.Length > 0)
            {
                if (arguments_raw[0] != '?')
                {
                    method_success = "?_isnt_present";
                    return method_success;
                }
            }

            string write_where = "";
            string name = "";
            string value = "";

            for (int i = 0; i < arguments_raw.Length; i++)
            {
                if (i == 0)
                {
                    write_where = "name";
                    continue;
                }
                if (arguments_raw[i] == '?')
                {
                    method_success = "invalid_syntax_?";
                    return method_success;
                }
                if (arguments_raw[i] == '-')
                {
                    arg_names.Add(name);
                    name = "";
                    if (write_where != "value")
                    {
                        write_where = "value";
                    }
                    else
                    {
                        method_success = "invalid_syntax_=";
                        return method_success;
                    }
                    continue;
                }
                if (arguments_raw[i] == '&')
                {
                    arg_values.Add(value);
                    value = "";
                    if (write_where != "name")
                    {
                        write_where = "name";
                    }
                    else
                    {
                        method_success = "invalid_syntax_&";
                        return method_success;
                    }
                    continue;
                }
                if (write_where == "name")
                {
                    name += arguments_raw[i];
                }
                else if (write_where == "value")
                {
                    value += arguments_raw[i];
                }
                if (i == arguments_raw.Length - 1)
                {
                    arg_values.Add(value);
                }
            }
            if (arg_names.Count != arg_values.Count)
            {
                method_success = "args_count_not_equal";
                return method_success;
            }

            int app_index = GetAppIndex(app);
            int method_ind = GetMethodIndex(method, app);
            if(app_index == -1)
            {
                method_success = "app_is_not_found";
                return method_success;
            }
            if (method_ind == -1)
            {
                method_success = "method_is_not_found";
                return method_success;
            }


            //Binded methods

            string binded_exe = method_bindings[app_index][method_ind];
            if(binded_exe == "none")
            {
                Send(stream, connection_id, "Method does nothing yet.");
                return method_success;
            }
            if(binded_exe != "hardcoded")
            {

                string auth_token = "";
                int index_found = -1;
                for (int i = 0; i < arg_names.Count; i++)
                {
                    if (arg_names[i] == "auth")
                    {
                        index_found = i;
                        break;
                    }
                }
                if (index_found != -1)
                {
                    auth_token = arg_values[index_found];
                }

                if(!CheckPermission(auth_token, method, app))
                {
                    method_success = "operation_not_permitted";
                    return method_success;
                }

                string output_txt = binded_exe + ".txt";
                string output_ = "none";


                LaunchBindExe(binded_exe, output_txt);

                DateTime d = DateTime.Now;
                while (true)
                {
                    if(DateTime.Now > d.AddSeconds(5))
                    {
                        Send(stream, connection_id, "Method time-out.");
                        return method_success;
                    }
                    string output = "";
                    while (true) 
                    {
                        try
                        {
                            output = File.ReadAllText(output_txt);
                            break;
                        }catch when (robust_enable){ }
                    }
                    if (output.StartsWith("Done!"))
                    {
                        output_ = output.Substring(6);
                        break;
                    }
                    if (output.StartsWith("Failed!"))
                    {
                        Send(stream, connection_id, "Method failed!");
                        return method_success;
                    }
                }

                Send(stream, connection_id, output_ + " ");
                return method_success;
            }


            //Hardcoded methods

            //_________________________________________
            //Shared methods part
            switch (method)
            {
                case "sign":
                    {
                        string username;
                        string password;
                        string auth_token = "";



                        int index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "username")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found == -1)
                        {
                            method_success = "username_not_provided";
                            return method_success;
                        }
                        username = arg_values[index_found];



                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "password")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found == -1)
                        {
                            method_success = "password_not_provided";
                            return method_success;
                        }

                        password = arg_values[index_found];

                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "auth")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            auth_token = arg_values[index_found];
                        }

                        

                        if (CheckPermission(auth_token, method, app))
                        {
                            method_success = SignIn(new string[][]
                            { 
                                new string[] {"username", username }, 
                                new string[] {"password", password } 
                            }, app);
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }

                        return method_success;
                    }
                case "log":
                    {
                        string username;
                        string password;
                        string auth_token = "";



                        int index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "username")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found == -1)
                        {
                            method_success = "username_not_provided";
                            return method_success;
                        }
                        username = arg_values[index_found];

                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "password")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found == -1)
                        {
                            method_success = "password_not_provided";
                            return method_success;
                        }
                        password = arg_values[index_found];

                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "auth")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            auth_token = arg_values[index_found];
                        }


                        if (CheckPermission(auth_token, method, app))
                        {
                            method_success = LogIn(new string[][]
                            {
                                new string[] {"username", username },
                                new string[] {"password", password }
                            }, app);
                            if (method_success == "success")
                            {
                                Send(stream, connection_id, "Auth token: " + GetUserAuthToken(username, app));
                            }
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }

                        return method_success;
                    }
            }
            //_______________________________________________

            

            //Root app's methods
            if (app == "root")
            {
                switch (method)
                {
                    case "list_ram_dbs":
                        {
                            string auth_token = "";

                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }

                            if (CheckPermission(auth_token, method, app))
                            {
                                Console.WriteLine("\n\n\n______________________________________");
                                DisplayRAMDatabaseStructure();
                                Console.WriteLine("______________________________________\n\n\n");
                                Send(stream, connection_id, "Success!");
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "new_app":
                        {
                            string app_name;
                            string auth_token = "";



                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "app_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "app_name_not_provided";
                                return method_success;
                            }
                            app_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                method_success = CreateApp(new string[][]
                                {
                                new string[] {"app_name", app_name },
                                });
                                Send(stream, connection_id, "Success!");
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "delete_app":
                        {
                            string app_name;
                            string auth_token = "";



                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "app_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "app_name_not_provided";
                                return method_success;
                            }
                            app_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                method_success = DeleteApp(app_name);
                                Send(stream, connection_id, "Success!");
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "new_db":
                        {
                            string auth_token = "";
                            string app_name;
                            string db_name;
                            string db_path;


                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "app_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "app_name_not_provided";
                                return method_success;
                            }
                            app_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "db_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "db_name_not_provided";
                                return method_success;
                            }
                            db_name = arg_values[index_found];

                             index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "db_path")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "db_path_not_provided";
                                return method_success;
                            }
                            db_path = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                method_success = CreateDatabase(new string[][]
                                {
                                    new string[] {"db_name", db_name},
                                    new string[] {"db_path", db_path},
                                }, app_name);
                                Send(stream, connection_id, "Success!");
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "delete_db":
                        {
                            string auth_token = "";
                            string app_name;
                            string db_name;


                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "app_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "app_name_not_provided";
                                return method_success;
                            }
                            app_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "db_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "db_name_not_provided";
                                return method_success;
                            }
                            db_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                method_success = DeleteDatabase(new string[][]
                                {
                                    new string[] {"db_name", db_name},
                                }, app_name);
                                Send(stream, connection_id, "Success!");
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "bind_code":
                        {
                            string auth_token = "";
                            string app_name;
                            string method_name;
                            string src_base64;


                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "app_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "app_name_not_provided";
                                return method_success;
                            }
                            app_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "method")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "method_name_not_provided";
                                return method_success;
                            }
                            method_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "src")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "src_not_provided";
                                return method_success;
                            }
                            src_base64 = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                method_success = BindAppToFunc(new string[][]
                                {
                                    new string[] {"app_name", app_name },
                                    new string[] {"method", method_name },
                                    new string[] {"src", src_base64},
                                }, app_name);
                                Send(stream, connection_id, "Success!");
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "new_method":
                        {
                            string auth_token = "";
                            string app_name;
                            string method_name;


                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "app_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "app_name_not_provided";
                                return method_success;
                            }
                            app_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "method_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "method_name_not_provided";
                                return method_success;
                            }
                            method_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                method_success = NewMethod(new string[][]
                                {
                                    new string[] {"method_name", method_name},
                                }, app_name);
                                Send(stream, connection_id, "Success!");
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "delete_method":
                        {
                            string auth_token = "";
                            string app_name;
                            string method_name;


                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "app_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "app_name_not_provided";
                                return method_success;
                            }
                            app_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "method_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "method_name_not_provided";
                                return method_success;
                            }
                            method_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                method_success = DeleteMethod(new string[][]
                                {
                                    new string[] {"method_name", method_name},
                                }, app_name);
                                Send(stream, connection_id, "Success!");
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                }
            }

            //Bard search app
            if(app == "bard_search")
            {
                switch (method)
                {
                    case "search":
                        {
                            string query;
                            string auth_token = "";
                            string mode;


                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "mode")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "mode_not_provided";
                                return method_success;
                            }
                            mode = arg_values[index_found];



                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "query")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "query_not_provided";
                                return method_success;
                            }
                            try
                            {

                                query = FromBase64(arg_values[index_found]);
                            }
                            catch when (robust_enable)
                            {
                                method_success = "invalid_query";
                                return method_success;
                            }

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                Console.WriteLine($"[BARD] Sending \"{query}\" with mode \"{mode}\" to bard.");
                                string response = BardGetResponse(query, mode);
                                //Send(stream, connection_id, "Success!");
                                Send(stream, connection_id, response);
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                }


            }

            //SVN Tunnel app
            if (app == "svntunnel")
            {
                switch (method)
                {
                    case "req":
                        {
                            string query;
                            string auth_token = "";


                            int index_found = -1;



                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "query")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "query_not_provided";
                                return method_success;
                            }
                            try
                            {

                                query = FromBase64(arg_values[index_found]);
                            }
                            catch when (robust_enable)
                            {
                                method_success = "invalid_query";
                                return method_success;
                            }

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }

                            if (true) //No check requered
                            {
                                Console.WriteLine($"[SVNTunnel] Sending \n\"{query}\"\n to svn.");
                                string response = SvnReq(query);
                                
                                Send(stream, connection_id, response);
                            }
                        }
                        break;
                    case "open_tunnel":
                        {
                            string hostname;
                            int port_;
                            string auth_token = "";


                            int index_found = -1;



                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "hostname")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "hostname_not_provided";
                                return method_success;
                            }
                            hostname = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "port")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "port_not_provided";
                                return method_success;
                            }
                            try
                            {
                                port_ = Int32.Parse(arg_values[index_found]);
                            }
                            catch
                            {
                                method_success = "invalid_port";
                                return method_success;
                            }


                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }

                            if (true) //No check requered
                            {
                                Console.WriteLine($"[SVNTunnel] Creating tunnel {hostname}:{port_}.");
                                string response = SvnOpenTunnel(hostname, port_);
                                Console.WriteLine($"[SVNTunnel] Tunnel successfully created! Id: {response}");
                                Send(stream, connection_id, response);
                            }
                        }
                        break;
                }


            }
            //ChatApp app
            if (app == "chatapp")
            {
                switch (method)
                {
                    case "create_channel":
                        {
                            string channel_name;
                            string auth_token = "";


                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "channel_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "channel_name_not_provided";
                                return method_success;
                            }
                            channel_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }

                            if (CheckPermission(auth_token, method, app))
                            {
                                string display_name = "";
                                int iter = 0;
                                while (true)
                                {
                                    display_name = channel_name + "#" + rand.Next() % 10 + "" + rand.Next() % 10 + "" + rand.Next() % 10 + "" + rand.Next() % 10;
                                    iter++;
                                    if (!chatapp_channel_names.Contains(display_name)) { break; }
                                    if (iter > 1000) return "channel_name_too_common";
                                }
                                string id = rand.Next() + "";
                                Console.WriteLine($"[ChatApp] Creating new channel: " + display_name);
                                string resp = ChatAppCreateChannel(display_name, auth_token, id);
                                Send(stream, connection_id, resp + "?name-"+display_name + "&id-"+id);
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "join_channel":
                        {
                            string channel_name;
                            string auth_token = "";


                            int index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "channel_name")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "channel_name_not_provided";
                                return method_success;
                            }
                            channel_name = arg_values[index_found];

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }

                            if (CheckPermission(auth_token, method, app))
                            {
                                Console.WriteLine($"[ChatApp] Joining channel: " + channel_name  + " : " + auth_token);
                                string resp = ChatAppJoinChannel(channel_name, auth_token);
                                Send(stream, connection_id, resp);
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "auth_tunnel":
                        {
                            string tunnel_id;
                            string auth_token = "";


                            int index_found = -1;



                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "tunnel_id")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "tunnel_id_not_provided";
                                return method_success;
                            }
                            tunnel_id = arg_values[index_found];


                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                string display_username = GetUserByToken(auth_token, app).ToLower();
                                Console.WriteLine($"[ChatApp] Authorizing tunnel: "+tunnel_id+" on auth_token: " + auth_token);
                                string resp = ChatAppAuthorizeTunnel(auth_token, tunnel_id);
                                Send(stream, connection_id, resp);
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                    case "msg":
                        {
                            string query;
                            string auth_token = "";
                            string chat_id;


                            int index_found = -1;



                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "query")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "query_not_provided";
                                return method_success;
                            }
                            try
                            {

                                query = FromBase64(arg_values[index_found]);
                            }
                            catch when (robust_enable)
                            {
                                method_success = "invalid_query";
                                return method_success;
                            }

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "chat_id")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found == -1)
                            {
                                method_success = "chat_id_not_provided";
                                return method_success;
                            }
                            chat_id = arg_values[index_found];
                            

                            index_found = -1;
                            for (int i = 0; i < arg_names.Count; i++)
                            {
                                if (arg_names[i] == "auth")
                                {
                                    index_found = i;
                                    break;
                                }
                            }
                            if (index_found != -1)
                            {
                                auth_token = arg_values[index_found];
                            }



                            if (CheckPermission(auth_token, method, app))
                            {
                                string display_username = GetUserByToken(auth_token, app).ToLower();
                                Console.WriteLine($"[ChatApp] ("+display_username+")" + query);
                                string resp = ChatApp_msg(query, auth_token, chat_id);
                                Send(stream, connection_id, resp);
                            }
                            else
                            {
                                method_success = "operation_not_permitted";
                            }
                        }
                        break;
                }


            }





            return method_success;
        }

        public static string[] ParseForApp(string msg)
        {
            if (msg[0] != '<')
            {
                throw new Exception();
            }
            bool is_app_part = true;
            string app = "";
            string left_over_msg = "";
            for (int i = 0; i < msg.Length; i++)
            {
                if (i == 0)
                {
                    continue;
                }
                if (msg[i] == '>')
                {
                    is_app_part = false;
                    continue;
                }
                if (is_app_part)
                {
                    app += msg[i];
                }
                else
                {
                    left_over_msg += msg[i];
                }
            }
            string[] res = new string[2] { app, left_over_msg };
            return res;
        }
        public static string[] ParseMessage(string message, string app)
        {
            string[] args = new string[4];
            string method = "";
            string port = "";
            bool is_method_section = false;
            bool is_port_section = false;
            string success_parse = "success";
            string message_body = "";
            int app_ind = GetAppIndex(app);
            //Parsing normal
            for (int i = 0; i < message.Length; i++)
            {
                if (message[i] == '\\' && (method == "" || is_method_section))
                {
                    is_method_section = !is_method_section;
                    is_port_section = false;
                    continue;
                }
                else
                if (message[i] == '~')
                {
                    port = "";
                    is_port_section = true;
                    continue;
                }
                if (is_method_section)
                {
                    method += message[i];
                }
                else if (is_port_section)
                {
                    port += message[i];
                }
                else
                {
                    message_body += message[i];
                }
            }

            if (method == "")
            {
                success_parse = "method_is_empty";
            }
            else if (!available_methods[app_ind].Contains(method))
            {
                //success_parse = "method_not_available";
            }

            if (success_parse == "success")
            {
                args[0] = port;
                args[1] = success_parse;
                args[2] = method;
                args[3] = message_body;
            }
            else
            {
                args = new string[2];
                args[0] = port;
                args[1] = success_parse;
            }
            return args;
        }


        //___________________________________
        //Functions used by apps

                        //root

        static string BindAppToFunc(string[][] parameters, string app)
        {
            string success_ = "success";
            int app_index = GetAppIndex(app);
            string method = parameters[GetParameterIndex(parameters, "method")][1];
            int method_index = GetMethodIndex(method, app);
            string source_code_base64 = parameters[GetParameterIndex(parameters, "src")][1];

            string exe_path = binded_functions_dir + app +"_"+method + "_function.exe";
            string src_path = binded_functions_src_dir + app + "_" + method + "_function_src.cs";
            CreateFile(exe_path);
            CreateFile(src_path);
            try
            {
                WriteToFile(src_path, FromBase64(source_code_base64));
            } catch when (robust_enable)
            {
                return "not_a_valid_base64_string";
            }
            CompileFile(src_path, exe_path);

            method_bindings[app_index][method_index] = exe_path;
            return success_;
        }
        static string DeleteMethod(string[][] parameters, string app)
        {
            string success_ = "success";
            int app_index = GetAppIndex(app);
            string method_name = parameters[GetParameterIndex(parameters, "method_name")][1];
            int method_ind = GetMethodIndex(method_name, app);

            //Method array descent
            {
                int l = available_methods[app_index].Length - 1;
                string[] method_new = new string[l];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == method_ind)
                    {
                        d++;
                    }
                    method_new[i] = available_methods[app_index][d];
                    d++;
                }
                available_methods[app_index] = method_new;
            }

            //Method Bindings array descent
            {
                int l = method_bindings[app_index].Length - 1;
                string[] method_binding_new = new string[l];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == method_ind)
                    {
                        d++;
                    }
                    method_binding_new[i] = method_bindings[app_index][d];
                    d++;
                }
                method_bindings[app_index] = method_binding_new;
            }

            //Method array descent
            {
                int l = method_permissions[app_index].Length - 1;
                string[] method_acl_new = new string[l];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == method_ind)
                    {
                        d++;
                    }
                    method_acl_new[i] = method_permissions[app_index][d];
                    d++;
                }
                method_permissions[app_index] = method_acl_new;
            }
            return success_;
        }
        static string NewMethod(string[][] parameters,string app)
        {
            string success_ = "success";
            int app_index = GetAppIndex(app);
            string method_name = parameters[GetParameterIndex(parameters, "method_name")][1];

            //Method array append
            {
                int l = available_methods[app_index].Length;
                string[] method_new = new string[l + 1];
                for (int i = 0; i < l; i++)
                {
                    method_new[i] = available_methods[app_index][i];
                }

                method_new[l] = method_name;
                available_methods[app_index] = method_new;
            }
            //Method bindings append
            {
                int l =method_bindings[app_index].Length;
                string[] method_bind_new = new string[l + 1];
                for (int i = 0; i < l; i++)
                {
                    method_bind_new[i] = method_bindings[app_index][i];
                }

                method_bind_new[l] = "none";
                method_bindings[app_index] = method_bind_new;
            }
            //Method ACLs append
            {
                int l = method_permissions[app_index].Length;
                string[] method_acls_new = new string[l + 1];
                for (int i = 0; i < l; i++)
                {
                    method_acls_new[i] = method_permissions[app_index][i];
                }

                method_acls_new[l] = "0";
                method_permissions[app_index] = method_acls_new;
            }

            return success_;
        }
        static string DeleteDatabase(string[][] parameters, string app)
        {
            string success_ = "success";
            int app_index = GetAppIndex(app);
            string database_name = parameters[GetParameterIndex(parameters, "db_name")][1];
            int database_index = GetDatabaseIndex(app,database_name);

            FileInfo file = new FileInfo(databases_dir + database_paths[app_index][database_index]);
            file.Delete();

            //Database names array descent
            {
                int l = database_names[app_index].Length - 1;
                string[] database_names_new = new string[l];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if(i == database_index)
                    {
                        d++;
                    }
                    database_names_new[i] = database_names[app_index][d];
                    d++;
                }
                database_names[app_index] = database_names_new;
            }

            //Database paths array descent
            {
                int l = database_paths[app_index].Length - 1;
                string[] database_paths_new = new string[l];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == database_index)
                    {
                        d++;
                    }
                    database_paths_new[i] = database_paths[app_index][d];
                    d++;
                }
                database_paths[app_index] = database_paths_new;
            }

            //Column names array descent
            {
                int l = column_names[app_index].Length - 1;
                string[][] column_names_new = new string[l][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == database_index)
                    {
                        d++;
                    }
                    column_names_new[i] = column_names[app_index][d];
                    d++;
                }
                column_names[app_index] = column_names_new;
            }

            //Default values array descent
            {
                int l = default_values[app_index].Length - 1;
                string[][] def_vals_new = new string[l][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == database_index)
                    {
                        d++;
                    }
                    def_vals_new[i] = default_values[app_index][d];
                    d++;
                }
                default_values[app_index] = def_vals_new;
            }

            //RAM Database array descent
            {
                int l = databases[app_index].Length - 1;
                List<string[]>[] databases_new = new List<string[]>[l];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == database_index)
                    {
                        d++;
                    }
                    databases_new[i] = databases[app_index][d];
                    d++;
                }
                databases[app_index] = databases_new;
            }

            return success_;
        }
        static string CreateDatabase(string[][] parameters, string app)
        {
            string success_ = "success";
            int app_index = GetAppIndex(app);
            string database_name = parameters[GetParameterIndex(parameters, "db_name")][1];
            string database_path = parameters[GetParameterIndex(parameters, "db_path")][1];

            CreateFile(databases_dir + database_path);

            //Database names array append
            {
                int l = database_names[app_index].Length;
                string[] database_names_new = new string[l + 1];
                for (int i = 0; i < l; i++)
                {
                    database_names_new[i] = database_names[app_index][i];
                }

                database_names_new[l] = database_name;
                database_names[app_index] = database_names_new;
            }

            //Database paths array append
            {
                int l = database_paths[app_index].Length;
                string[] database_paths_new = new string[l + 1];
                for (int i = 0; i < l; i++)
                {
                    database_paths_new[i] = database_paths[app_index][i];
                }

                database_paths_new[l] = database_path;
                database_paths[app_index] = database_paths_new;
            }

            //Column names array append
            {
                int l = column_names[app_index].Length;
                string[][] column_names_new = new string[l + 1][];
                for (int i = 0; i < l; i++)
                {
                    column_names_new[i] = column_names[app_index][i];
                }

                column_names_new[l] = new string[] { "null" };
                column_names[app_index] = column_names_new;
            }

            //Default values array append
            {
                int l = default_values[app_index].Length;
                string[][] def_vals_new = new string[l + 1][];
                for (int i = 0; i < l; i++)
                {
                    def_vals_new[i] = default_values[app_index][i];
                }

                def_vals_new[l] = new string[] { "null" };
                default_values[app_index] = def_vals_new;
            }

            //RAM Databases array append
            {
                int l = databases[app_index].Length;
                List<string[]>[] databases_new = new List<string[]>[l + 1];
                for (int i = 0; i < l; i++)
                {
                    databases_new[i] = databases[app_index][i];
                }

                databases_new[l] = new List<string[]>();
                databases[app_index] = databases_new;
            }
            return success_;
        }

        static string CreateApp(string[][] parameters)
        {
            string success_ = "success";

            string new_app_name = parameters[GetParameterIndex(parameters, "app_name")][1];

            //App array append
            {
                string[] new_app_arr = new string[apps.Length + 1];
                for (int i = 0; i < apps.Length; i++)
                {
                    new_app_arr[i] = apps[i];
                }

                new_app_arr[apps.Length] = new_app_name;
                apps = new_app_arr;
            }

            //Database names array append
            {
                int l = database_names.Length;
                string[][] database_names_new = new string[l + 1][];
                for (int i = 0; i < l; i++)
                {
                    database_names_new[i] = database_names[i];
                }

                database_names_new[l] = new string[]{"users", "auth_tokens" };
                database_names = database_names_new;
            }

            //Database paths array append
            {
                int l = database_paths.Length;
                string[][] database_paths_new = new string[l + 1][];
                for (int i = 0; i < l; i++)
                {
                    database_paths_new[i] = database_paths[i];
                }

                database_paths_new[l] = new string[] { new_app_name+@"\us.db", new_app_name+@"\au.db" };

                //Directory.CreateDirectory(databases_dir + new_app_name);
                foreach(string p in database_paths_new[l])
                {
                    //FileStream fs = new FileStream(databases_dir + p, FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite);
                    //fs.Close();
                    //File.Create(databases_dir + p).Close();
                    CreateFile(databases_dir + p);
                }
                database_paths = database_paths_new;
            }

            //Roles array append
            {
                int l = roles.Length;
                string[][] roles_new = new string[l + 1][];
                for (int i = 0; i < l; i++)
                {
                    roles_new[i] = roles[i];
                }

                roles_new[l] = new string[] { "Admin", "User", "Anonymous" };
                roles = roles_new;
            }

            //Column names array append
            {
                int l = column_names.Length;
                string[][][] column_names_new = new string[l + 1][][];
                for (int i = 0; i < l; i++)
                {
                    column_names_new[i] = column_names[i];
                }

                column_names_new[l] = new string[][]
                {
                    new string[] { "username", "password", "role"},
                    new string[] { "username", "auth_token"}
                };
                column_names = column_names_new;
            }

            //Def vals array append
            {
                int l = default_values.Length;
                string[][][] def_vals_new = new string[l + 1][][];
                for (int i = 0; i < l; i++)
                {
                    def_vals_new[i] = default_values[i];
                }

                def_vals_new[l] = new string[][]
                {
                    new string[] { "null", "null", "User"},
                    new string[] { "null", "null"},
                };
                default_values = def_vals_new;
            }

            //Methods append
            {
                int l = available_methods.Length;
                string[][] methods_new = new string[l + 1][];
                for (int i = 0; i < l; i++)
                {
                    methods_new[i] = available_methods[i];
                }

                methods_new[l] = new string[] { "sign", "log" };
                available_methods = methods_new;
            }

            //Methods Bindings append
            {
                int l = method_bindings.Length;
                string[][] methods_binding_new = new string[l + 1][];
                for (int i = 0; i < l; i++)
                {
                    methods_binding_new[i] = method_bindings[i];
                }

                methods_binding_new[l] = new string[] { "hardcoded", "hardcoded" };
                method_bindings = methods_binding_new;
            }

            //Method ACLs append
            {
                int l = method_permissions.Length;
                string[][] methods_acls_new = new string[l + 1][];
                for (int i = 0; i < l; i++)
                {
                    methods_acls_new[i] = method_permissions[i];
                }

                methods_acls_new[l] = new string[] { "0:2", "0:2" };
                method_permissions = methods_acls_new;
            }

            //RAM Databases array append
            {
                int l = databases.Length;
                List<string[]>[][] databases_new = new List<string[]>[l + 1][];
                for (int i = 0; i < l; i++)
                {
                    databases_new[i] = databases[i];
                }

                databases_new[l] = new List<string[]>[]
                {
                    new List<string[]>(),
                    new List<string[]>(),
                };
                databases = databases_new;
            }
            
            SignIn(new string[][] 
            {
                new string[] {"username", "admin"},
                new string[] {"password", "admin"},
                new string[] {"role", "Admin"},
            }, new_app_name);
            
            return success_;
        }

        static string DeleteApp(string app)
        {
            string success_ = "success";

            int app_index = GetAppIndex(app);

            //App array append
            {
                string[] new_app_arr = new string[apps.Length - 1];
                int d = 0;
                for (int i = 0; i < apps.Length-1; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    new_app_arr[i] = apps[d];
                    
                    d++;
                }
                apps = new_app_arr;
            }

            //Database names array append
            {
                int l = database_names.Length - 1;
                string[][] database_names_new = new string[l][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    database_names_new[i] = database_names[d];
                    d++;
                }
                database_names = database_names_new;
            }

            //Database paths array append
            {
                int l = database_paths.Length - 1;
                string[][] database_paths_new = new string[l][];

                DirectoryInfo di = new DirectoryInfo(databases_dir + app);

                foreach (FileInfo file in di.GetFiles())
                {
                    file.Delete();
                }

                while (true)
                {
                    try
                    {
                        Directory.Delete(databases_dir + app);
                        break;
                    }
                    catch  { }
                }

                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    database_paths_new[i] = database_paths[d];
                    d++;
                }
                
                database_paths = database_paths_new;
            }

            //Roles array append
            {
                int l = roles.Length - 1;
                string[][] roles_new = new string[l][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    roles_new[i] = roles[d];
                    d++;
                }

                roles = roles_new;
            }

            //Column names array append
            {
                int l = column_names.Length - 1;
                string[][][] column_names_new = new string[l][][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    column_names_new[i] = column_names[d];
                    d++;
                }
                column_names = column_names_new;
            }

            //Def vals array append
            {
                int l = default_values.Length - 1;
                string[][][] def_vals_new = new string[l][][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    def_vals_new[i] = default_values[d];
                    d++;
                }
                default_values = def_vals_new;
            }

            //Methods append
            {
                int l = available_methods.Length - 1;
                string[][] methods_new = new string[l][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    methods_new[i] = available_methods[d];
                    d++;
                }

                available_methods = methods_new;
            }

            //Method Bindings append
            {
                int l = method_bindings.Length - 1;
                string[][] methods_binding_new = new string[l][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    methods_binding_new[i] = method_bindings[d];
                    d++;
                }

                method_bindings = methods_binding_new;
            }

            //Method ACLs append
            {
                int l = method_permissions.Length - 1;
                string[][] methods_acls_new = new string[l][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    methods_acls_new[i] = method_permissions[d];
                    d++;
                }
                method_permissions = methods_acls_new;
            }
            //RAM Databases array append
            {
                int l = databases.Length - 1;
                List<string[]>[][] databases_new = new List<string[]>[l][];
                int d = 0;
                for (int i = 0; i < l; i++)
                {
                    if (i == app_index)
                    {
                        d++;
                    }
                    databases_new[i] = databases[d];
                    d++;
                }

                databases = databases_new;
            }

            return success_;
        }

        //Shared

        static string LogIn(string[][] parameters, string app)
        {
            string success_login = "success";
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "users");
            int username_index = GetParameterIndex(parameters, "username");
            int password_index = GetParameterIndex(parameters, "password");
            string username = parameters[username_index][1];
            string password = parameters[password_index][1];
            if (!CheckUserPresence(username, app))
            {
                success_login = "username_not_found";
                return success_login;
            }
            if (databases[app_index][db_index][GetUserID(username, app)][1] != password)
            {
                success_login = "password_incorrect";
                return success_login;
            }

            return success_login;
        }
        static string SignIn(string[][] parameters, string app)
        {
            string success_signin = "success";
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "users");
            int username_index = GetParameterIndex(parameters, "username");
            int password_index = GetParameterIndex(parameters, "password");
            int role_index = GetParameterIndex(parameters, "role");
            string username = parameters[username_index][1];
            string password = parameters[password_index][1];
            string role = role_index != -1 ? parameters[role_index][1] : "null";
            if (CheckUserPresence(username, app))
            {
                success_signin = "username_already_present";
                return success_signin;
            }
            string[] new_entry = new string[default_values[app_index][db_index].Length];
            for(int i = 0; i < new_entry.Length; i++)
            {
                if(column_names[app_index][db_index][i] == "username")
                {
                    new_entry[i] = username;
                }
                if (column_names[app_index][db_index][i] == "password")
                {
                    new_entry[i] = password;
                }
                if (default_values[app_index][db_index][i] != "null")
                {
                    new_entry[i] = default_values[app_index][db_index][i];
                }


                if(column_names[app_index][db_index][i] == "role" && role != "null")
                {
                    new_entry[i] = role;
                }
            }
            databases[app_index][db_index].Add(new_entry);
            return success_signin;
        }
                     //Chores
        static string AddChore(string[][] parameters, string app)
        {
            string success_adding = "success";
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "chores");
            int username_sender_index = GetParameterIndex(parameters, "username_sender");
            int username_reciever_index = GetParameterIndex(parameters, "username_reciever");
            int chore_type_index = GetParameterIndex(parameters, "chore_type");
            int chore_desc_index = GetParameterIndex(parameters, "chore_desc");

            string username_sender = parameters[username_sender_index][1];
            string username_reciever = parameters[username_reciever_index][1];
            string chore_type = parameters[chore_type_index][1];
            string chore_desc = parameters[chore_desc_index][1];

            string[] new_entry = new string[default_values[app_index][db_index].Length];
            for (int i = 0; i < new_entry.Length; i++)
            {
                if (column_names[app_index][db_index][i] == "username_sender")
                {
                    new_entry[i] = username_sender;
                }
                if (column_names[app_index][db_index][i] == "username_reciever")
                {
                    new_entry[i] = username_reciever;
                }
                if (column_names[app_index][db_index][i] == "chore_type")
                {
                    new_entry[i] = chore_type;
                }
                if (column_names[app_index][db_index][i] == "chore_desc")
                {
                    new_entry[i] = chore_desc;
                }
                if (default_values[app_index][db_index][i] != "null")
                {
                    new_entry[i] = default_values[app_index][db_index][i];
                }
            }
            databases[app_index][db_index].Add(new_entry);


            return success_adding;
        }

                  //Bard
        public static string BardGetResponse(string input, string mode)
        {
            string[] system_messages = new string[]
            {
                "You are in conversation. Respond in a short way and chatty. You can respond only your response. Your name is 'AI assistant' unless user wants to change it. You MUST provide your response in a form of '@Your name: your response' You MUST NOT exceed the limit of 300 characters in your answer. You MUST only provide your answer. Your message history is: ~",
                "You are in advanced search engine. Respond using long paragraphs and provide as much information as you can. Your topic is: ~",
            };
            int ind = -1;
            switch (mode)
            {
                case "conversation":
                    ind = 0;
                    break;
                case "deep_search":
                    ind = 1;
                    break;
                default:
                    return "Mode is incorrect";
            }
            string request = system_messages[ind] + input.Replace("\n", string.Empty) + "~";
            return BardParseResponse(BardGetRawResponse(request));
        }
        public static string BardGetRawResponse(string input)
        {
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };

            var client = new HttpClient(handler);

            var request = new HttpRequestMessage(HttpMethod.Post, "https://bard.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?bl=boq_assistant-bard-web-server_20230404.15_p0&_reqid=1440589");

            var cookie = new Cookie("__Secure-1PSID", bard_api_keys[bard_api_key_num])
            {
                Secure = true,
                HttpOnly = true,
                Domain = "bard.google.com"
            };

            handler.CookieContainer.Add(cookie);
            request.Headers.TryAddWithoutValidation("Origin", "https://bard.google.com");

            var content = new StringContent("f.req=%5Bnull%2C%22%5B%5B%5C%22" + input + "%5C%22%5D%2Cnull%2C%5B%5C%22" + "%5C%22%2C%5C%22" + "%5C%22%2C%5C%22" + "%5C%22%5D%5D%22%5D&at=" + bard_at_vars[bard_api_key_num] + "&", Encoding.UTF8, "application/x-www-form-urlencoded");

            request.Content = content;

            var response = client.SendAsync(request).GetAwaiter().GetResult();

            var responseContent = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            
            return responseContent;
        }
        public static string BardParseResponse(string input)
        {
            int offset = 6;
            string offsetted = input.Substring(offset, input.Length - offset);
            string json = offsetted;

            Console.ForegroundColor = ConsoleColor.Blue;
            //Console.WriteLine("\n" + json + "\n");
            Console.ForegroundColor = ConsoleColor.Green;
            var substr = JsonNode.Parse(json);
            
            //Console.WriteLine(substr[0][2].ToString());
            if (substr[0][2] == null)
            {
                bard_api_key_num++;
                if(bard_api_key_num == bard_api_keys.Length)
                {
                    bard_api_key_num = 0;
                }
                return "Rate limit is reached!";
            }
            json = substr[0][2].ToString();
            substr = JsonNode.Parse(json);
            return substr[0][0].ToString();
        }

        //Svn
        public static string SvnReq(string input)
        {
            string body = "";
            if (input.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries).Length > 1)
            {
                body = input.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries)[1];
            }
            string url = "";
            string method = input.Split(' ')[0];
            string host_ = "";
            List<string> header_lines = input.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries)[0].Split(new string[] { "\n" }, StringSplitOptions.RemoveEmptyEntries).ToList();
            header_lines.RemoveAt(0);
            List<Cookie> cookies_list = new List<Cookie>();
            foreach (string line in header_lines)
            {
                string[] b = line.Split(':');
                string[] c = new string[2];
                c[0] = b[0];
                for(int i = 1; i < b.Length; i++)
                {
                    c[1] += b[i];
                    if (i == b.Length - 1) break;
                    c[1] += ":";
                }
                var cookie = new Cookie(c[0], c[1])
                {
                    Secure = true,
                    HttpOnly = true,
                };
                if (c[0] == "Host")
                {
                    string hos = "";
                    for(int i =0; i < c[1].Length; i++)
                    {
                        if (c[1][i] == ' ') { continue; }
                        hos += c[1][i];
                    }

                    url = "http://" + hos + input.Split(' ')[1];
                    if(input.Split(' ')[1].StartsWith("http://") || input.Split(' ')[1].StartsWith("https://"))
                    {
                        url = input.Split(' ')[1];
                    }
                    host_ = "http://" + hos;
                }
            }
            return GetRawResponse(body, method, url,host_, cookies_list);
        }
        public static string SvnOpenTunnel(string hostname, int port)
        {
            TcpClient tcpClient = new TcpClient(hostname, port);
            NetworkStream networkStream = tcpClient.GetStream();
            string tunnel_id = rand.Next() + "";
            svn_tunnels_clients.Add(tcpClient);
            svn_tunnels_streams.Add(networkStream);
            svn_tunnel_ids.Add(tunnel_id);
            string tunnel_id_char10 = new String('0', 10-tunnel_id.Length) +tunnel_id;
            return tunnel_id_char10;
        }
        public static byte[] SvnTunnelReq(string tunnel_id, byte[] bytes)
        {
            int tunnel_ind = SVNGetTunnelIndById(tunnel_id);
            TcpClient client = svn_tunnels_clients[tunnel_ind];
            NetworkStream stream = svn_tunnels_streams[tunnel_ind];
            stream.Write(bytes, 0, bytes.Length);
            List<byte> bytes_res = new List<byte>();
            client.Client.ReceiveTimeout = 1000;
            while (true)
            {
                try
                {
                    bytes_res.Add((byte)stream.ReadByte());
                }
                catch { break; }
            }
            client.Client.ReceiveTimeout = 0;
            return bytes_res.ToArray();
        }
        public static string GetRawResponse(string body, string method, string url,string host, List<Cookie> cookies)
        {
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };

            var client = new HttpClient(handler);

            HttpMethod m = HttpMethod.Get;
            switch (method.ToLower())
            {
                case "get":
                    m = HttpMethod.Get;
                    break;
                case "post":
                    m = HttpMethod.Post;
                    break;
                case "put":
                    m = HttpMethod.Put;
                    break;
                case "options":
                    m = HttpMethod.Options;
                    break;
            }

            var request = new HttpRequestMessage(m, url);

            foreach (Cookie f in cookies) {

                handler.CookieContainer.Add(f);
            }

            request.Headers.TryAddWithoutValidation("Origin", host);
            if (method.ToLower() != "get")
            {
                var content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");

                request.Content = content;
            }
            try
            {
                var response = client.SendAsync(request).GetAwaiter().GetResult();
                var responseContent = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var responseHeaders = response.Headers;
                string headers_str = "";
                headers_str += ("HTTP/" + response.Version+" "+(int)response.StatusCode+" " + response.ReasonPhrase);
                foreach(var g in responseHeaders)
                {
                    string val_str = "";
                    foreach(var v in g.Value)
                    {
                        val_str += v + " ";   
                    }
                    headers_str += "\n" + g.Key + ": " + val_str;
                }
                return headers_str + "\r\n\r\n" + responseContent;
            }
            catch(Exception c)
            {
                Console.WriteLine(c.Message);
                return "Invalid URL";
            }
        }

        //ChatApp

        static void ChatAppMainframe()
        {
            Thread messages_queue_thread = new Thread(() =>
            {
                while (true)
                {
                    if (messages_queue.Count <= 0) continue;
                    List<string[]> messages_current = new List<string[]>();
                    for(int i = 0; i < messages_queue.Count; i++)
                    {
                        messages_current.Add(CopyArray(messages_queue[i]));
                    }
                    for(int i = 0; i < messages_current.Count; i++)
                    {
                        messages_queue.RemoveAt(0);
                    }
                    foreach (string[] message in messages_current)
                    {
                        bool valid = ChatAppValidateMessage(message);
                        Console.WriteLine("Message is valid: "+ valid);
                        if (valid)
                        {
                            List<NetworkStream> all_tunnels_members = new List<NetworkStream>();
                            string[] auth_tokens_members = GetAuthTokensByChatID(message[1]);
                            Console.WriteLine("Sending to " + auth_tokens_members.Length + "members...");
                            foreach(string a in auth_tokens_members)
                            {
                                NetworkStream[] tunnels_per_auth = ChatAppGetTunnelsByAuthToken(a);
                                foreach(NetworkStream s in tunnels_per_auth)
                                {
                                    all_tunnels_members.Add(s);
                                }
                            }
                            Console.WriteLine("Sending to " + all_tunnels_members.Count + "clients...");
                            foreach (NetworkStream stream_member in all_tunnels_members)
                            {
                                WriteBytesToNS(stream_member, Encoding.ASCII.GetBytes("[new_msg]?msg-" + message[2] + "&display_name-" + GetUserByToken(message[0], "chatapp") + "&chat_id-" + message[1]));
                            }
                        }
                    }
                }
            });
            messages_queue_thread.Start();
        }
        static string[] CopyArray(string[] array)
        {
            string[] array2 = new string[array.Length];
            for(int i =0; i< array.Length; i++)
            {
                array2[i] = array[i];
            }
            return array2;
        }
        
        static string ChatAppCreateChannel(string channel_name, string auth_token, string id)
        {
            chatapp_channel_ids.Add(id);
            chatapp_channel_names.Add(channel_name);
            List<string> m = new List<string>
            {
                auth_token
            };
            chatapp_channels_members_auths.Add(m);
            return "success";
        }
        static string ChatAppJoinChannel(string channel_name, string auth_token)
        {
            int ind = ChatAppGetChannelByName(channel_name);
            if (ind == -1) return "channel_name_doesnt_exist";
            if (chatapp_channels_members_auths[ind].Contains(auth_token)) { return "already_a_member"; }
            chatapp_channels_members_auths[ind].Add(auth_token);
            return "success";
        }
        static string ChatApp_msg(string msg, string auth_token, string chat_id)
        {
            messages_queue.Add(new string[] {auth_token, chat_id, msg, rand.Next()+""});
            return "success";
        }
        static string ChatAppAuthorizeTunnel(string auth_token, string tunnel_id)
        {
            int tunnel_ind = ChatAppGetTunnelIndByID(tunnel_id);
            if (chatapp_tunnel_auths[tunnel_ind] == "")
            {
                chatapp_tunnel_auths[tunnel_ind] = auth_token;
            }
            else { return "already_authed"; }
            return "success";
        }
        static bool ChatAppMessageSending(string[] message)
        {
            return false;
        }
        static bool ChatAppValidateMessage(string[] message)
        {
            if (message == null) return false;
            if (message.Length != 4) return false;
            string authtoken = message[0];
            string chat_id = message[1];
            string message_body = message[2];
            int chat_ind = chatapp_channel_ids.IndexOf(chat_id);
            if (chat_ind == -1) return false;
            foreach(string auth_token in chatapp_channels_members_auths[chat_ind])
            {
                if (authtoken == auth_token) return true;
            }
            return false;
        }
        static string[] GetAuthTokensByChatID(string chat_id)
        {
            return chatapp_channels_members_auths[chatapp_channel_ids.IndexOf(chat_id)].ToArray();
        }
        static NetworkStream[] ChatAppGetTunnelsByAuthToken(string auth)
        {
            List<NetworkStream> tunnels = new List<NetworkStream>();
            int ind = 0;
            foreach(string s in chatapp_tunnel_auths)
            {
                if(s == auth)
                {
                    tunnels.Add(chatapp_tunnels_streams[ind]);
                }
                ind++;
            }
            return tunnels.ToArray();
        }

        //___________________________________



        static int SVNGetTunnelIndById(string id)
        {
            return svn_tunnel_ids.IndexOf(id);
        }
        static int ChatAppGetTunnelIndByID(string id)
        {
            return chatapp_tunnel_ids.IndexOf(id);
        }
        static int ChatAppGetChannelByName(string name)
        {
            return chatapp_channel_names.IndexOf(name);
        }
        static int GetParameterIndex(string[][] parameters, string parameter_name)
        {
            for(int i = 0; i < parameters.Length; i++)
            {
                if(parameters[i][0] == parameter_name)
                {
                    return i;
                }
            }
            return -1;
        }
        static int GetMethodIndex(string method_name,string app_name)
        {
            int app_ind = GetAppIndex(app_name);

            int ind = 0;
            bool found = false;
            foreach (string method in available_methods[app_ind])
            {
                if (method_name == method)
                {
                    found = true;
                    break;
                }
                ind++;
            }
            if (!found)
            {
                return -1;
            }
            return ind;
        }
        static int GetDatabaseIndex(string app_name, string database_name)
        {
            int app_ind = GetAppIndex(app_name);

            int ind = 0;
            bool found = false;
            foreach (string db_name in database_names[app_ind])
            {
                if (db_name == database_name)
                {
                    found = true;
                    break;
                }
                ind++;
            }
            if (!found)
            {
                return -1;
            }
            return ind;


        }
        static int GetAppIndex(string app_name)
        {
            int ind = 0;
            bool found = false;
            foreach (string app in apps)
            {
                if (app == app_name)
                {
                    found = true;
                    break;
                }
                ind++;
            }
            if (!found)
            {
                return -1;
            }
            return ind;
        }
        static string GetUserAuthToken(string username, string app)
        {
            string auth_token;
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "auth_tokens");
            int db_index2 = GetDatabaseIndex(app, "users");
            if (CheckAuthTokenPresence(username, app))
            {
                auth_token = databases[app_index][db_index][GetUserToken(username, app)][1];
            }
            else
            {
                auth_token = CreateMD5(databases[app_index][db_index2][GetUserID(username, app)][1] + rand.Next());
                databases[app_index][db_index].Add(new string[] { username, auth_token });
            }
            return auth_token;
        }
        static bool CheckAuthTokenPresence(string username, string app)
        {
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "auth_tokens");
            foreach (string[] user in databases[app_index][db_index])
            {
                if (user[0] == username)
                {
                    return true;
                }
            }
            return false;
        }
        static bool CheckAuthTokenPresenceByToken(string token, string app)
        {
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "auth_tokens");
            foreach (string[] user in databases[app_index][db_index])
            {
                if (user[1] == token)
                {
                    return true;
                }
            }
            return false;
        }
        static int GetUserToken(string username, string app)
        {
            int index = 0;
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "auth_tokens");
            foreach (string[] user in databases[app_index][db_index])
            {
                if (user[0] == username)
                {
                    return index;
                }
                index++;
            }
            return -1;
        }
        static int GetUserTokenByToken(string token, string app)
        {
            int index = 0;
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "auth_tokens");
            foreach (string[] user in databases[app_index][db_index])
            {
                if (user[1] == token)
                {
                    return index;
                }
                index++;
            }
            return -1;
        }
        static string GetUserByToken(string token, string app)
        {
            string username = "";
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "auth_tokens");
            if (CheckAuthTokenPresenceByToken(token, app))
            {
                username = databases[app_index][db_index][GetUserTokenByToken(token, app)][0];
            }
            return username;
        }
        static bool CheckUserPresence(string username, string app)
        {
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "users");
            foreach (string[] user in databases[app_index][db_index])
            {
                if (user[0] == username)
                {
                    return true;
                }
            }
            return false;
        }
        static int GetUserID(string username, string app)
        {
            int index = 0;
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "users");
            foreach (string[] user in databases[app_index][db_index])
            {
                if (user[0] == username)
                {
                    return index;
                }
                index++;
            }
            return -1;
        }

        static int GetConnectionInd(int connection_id)
        {
            int index = 0;
            foreach (int c_id in active_connection_ids)
            {
                if (connection_id == c_id)
                {
                    return index;
                }
                index++;
            }
            return -1;
        }
        static bool CheckPermission(string auth_token, string method, string app)
        {
            if(app != "root")
            {
                if (CheckPermission(auth_token, "sign", "root")) return true;
            }
            string role;
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "users");
            if (auth_token == "" || db_index == -1)
            {
                role = "Anonymous";
                
            }
            else if (CheckAuthTokenPresenceByToken(auth_token, app))
            {
                role = databases[app_index][db_index][GetUserID(GetUserByToken(auth_token, app), app)][2];
            }
            else
            {
                role = "Anonymous";
            }
            int role_index = 0;
            foreach (string r in roles[app_index])
            {
                if (role == r)
                {
                    break;
                }
                role_index++;
            }
            
            int method_index = 0;
            foreach (string r in available_methods[app_index])
            {
                if (method == r)
                {
                    break;
                }
                method_index++;
            }
            string[] method_permission = method_permissions[app_index][method_index].Split(':');
            Console.WriteLine("[PERMISSION CHECKING] " + role + " " + role_index + " " + auth_token + " " + method_permissions[app_index][method_index] + " " + db_index);
            foreach (string role_test in method_permission)
            {
                if (role_index == Int32.Parse(role_test))
                {
                    return true;
                }
            }
            return false;

        }

        
        static void ClearRAMDatabases()
        {
            for (int i = 0; i < database_names.Length; i++)
            {
                for (int j = 0; j < database_names[i].Length; j++)
                {
                    databases[i][j].Clear();
                }
            }
        }
        static void InitRAMDatabases()
        {
            databases = new List<string[]>[database_names.Length][];
            for (int i = 0; i < database_names.Length; i++)
            {
                databases[i] = new List<string[]>[database_names[i].Length];
                for (int j = 0; j < database_names[i].Length; j++)
                {
                    databases[i][j] = new List<string[]>();
                }
            }
        }
        static void DisplayArray(string[] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                Console.WriteLine("-");
                Console.WriteLine(arr[i]);
            }
        }
        static void DisplayArray(string[][] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                Console.WriteLine("-");
                for (int j = 0; j < arr[i].Length; j++)
                {
                    Console.WriteLine("----");

                    Console.WriteLine(arr[i][j]);
                }
            }
        }
        static void DisplayArray(string[][][] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                Console.WriteLine("-");
                for (int j = 0; j < arr[i].Length; j++)
                {
                    Console.WriteLine("----");
                    for (int k = 0; k < arr[i][j].Length; k++)
                    {
                        Console.WriteLine("-------");

                        Console.WriteLine(arr[i][j][k]);
                    }
                }
            }
        }
        static void DisplayRAMDatabaseStructure()
        {
            for (int i = 0; i < database_names.Length; i++)
            {
                Console.WriteLine("-" + apps[i]);
                for (int j = 0; j < database_names[i].Length; j++)
                {
                    Console.WriteLine("----" + database_names[i][j]);
                    for (int k = 0; k < databases[i][j].Count; k++)
                    {
                        string[] entry = databases[i][j][k];
                        Console.Write("-------");
                        bool is_col_null = false;
                        if (column_names[i][j][0] == "null")
                        {
                            is_col_null = true;
                        }
                        for (int l = 0; l < entry.Length; l++)
                        {
                            if (!is_col_null)
                            {
                                Console.Write(column_names[i][j][l] + ":");
                            }
                            Console.Write(entry[l]);
                            if (l != entry.Length - 1)
                            {
                                Console.Write("  ");
                            }
                        }
                        Console.WriteLine();
                    }
                }
            }
        }
        static void ClearDatabases()
        {
            int inc_app = 0;
            foreach (string[] app_dbs in database_paths)
            {
                if (inc_app == GetAppIndex("root"))
                {
                    inc_app++;
                    continue;
                }
                foreach (string db_path in app_dbs)
                {
                    FileStream fs = new FileStream(databases_dir + db_path, FileMode.Truncate, FileAccess.ReadWrite, FileShare.ReadWrite);
                    fs.Close();
                }
                inc_app++;
            }
        }
        static void WriteDataToDatabase()
        {
            ClearDatabases();
            int inc_app = 0;

            foreach (string[] app_dbs in database_paths)
            {
                if(inc_app == GetAppIndex("root"))
                {
                    inc_app++;
                    continue;
                }
                int inc_db = 0;
                foreach (string db_path in app_dbs)
                {
                    FileStream fs = new FileStream(databases_dir + db_path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                    StreamWriter writer = new StreamWriter(fs);
                    foreach (string[] item in databases[inc_app][inc_db])
                    {
                        string line_u = "";
                        for (int i = 0; i < item.Length; i++)
                        {
                            line_u += item[i];
                            if (i == item.Length - 1)
                            {
                                break;
                            }
                            line_u += "~";
                        }
                        writer.WriteLine(line_u);
                    }
                    writer.Close();
                    inc_db++;
                }
                inc_app++;
            }
        }
        static void ReadDataFromDatabase()
        {
            InitRAMDatabases();
            ClearRAMDatabases();
            

            int inc_app = 0;
            
            foreach (string[] app_dbs in database_paths)
            {
                int inc_db = 0;
                foreach (string db_path in app_dbs)
                {
                    FileStream fs = new FileStream(databases_dir + db_path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                    StreamReader reader = new StreamReader(fs);
                    while (true)
                    {
                        string line = reader.ReadLine();
                        if (line == null || line == "")
                        {
                            break;
                        }
                        string[] param = line.Split('~');
                        databases[inc_app][inc_db].Add(param);
                    }
                    reader.Close();
                    inc_db++;
                }
                inc_app++;
            }
        }
        static void ReadRootDatabase()
        {
            int root_app_index = GetAppIndex("root");
            for (int i = 0; i < database_paths[root_app_index].Length; i++)
            {
                FileStream fs = new FileStream(databases_dir + database_paths[root_app_index][i], FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                StreamReader reader = new StreamReader(fs);
                switch (database_names[root_app_index][i])
                {
                    case "users":
                        {
                            List<string[]> users_list = new List<string[]>();
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                users_list.Add(line.Split('~'));
                            }
                            root_users = new string[users_list.Count][];
                            for (int j = 0; j < users_list.Count; j++)
                            {
                                root_users[j] = users_list[j];
                            }
                        }
                        break;
                    case "auth_tokens":
                        {
                            List<string[]> auth_tokens_list = new List<string[]>();
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                auth_tokens_list.Add(line.Split('~'));
                            }
                            root_auth_tokens = new string[auth_tokens_list.Count][];
                            for (int j = 0; j < auth_tokens_list.Count; j++)
                            {
                                root_auth_tokens[j] = auth_tokens_list[j];
                            }
                        }
                        break;
                    case "apps":
                        {
                            apps = reader.ReadLine().Split('~');
                        }
                        break;
                    case "database_names":
                        {
                            List<string[]> db_names_list = new List<string[]>(); 
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                db_names_list.Add(line.Split('~'));
                            }
                            database_names = new string[db_names_list.Count][];
                            for(int j = 0; j < db_names_list.Count; j++)
                            {
                                database_names[j] = db_names_list[j];
                            }
                        }
                        break;
                    case "database_paths":
                        {
                            List<string[]> db_paths_list = new List<string[]>();
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                db_paths_list.Add(line.Split('~'));
                            }
                            database_paths = new string[db_paths_list.Count][];
                            for (int j = 0; j < db_paths_list.Count; j++)
                            {
                                database_paths[j] = db_paths_list[j];
                            }
                        }
                        break;
                    case "roles":
                        {
                            List<string[]> roles_list = new List<string[]>();
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                roles_list.Add(line.Split('~'));
                            }
                            roles = new string[roles_list.Count][];
                            for (int j = 0; j < roles_list.Count; j++)
                            {
                                roles[j] = roles_list[j];
                            }
                        }
                        break;
                    case "methods":
                        {
                            List<string[]> methods_list = new List<string[]>();
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                methods_list.Add(line.Split('~'));
                            }
                            available_methods = new string[methods_list.Count][];
                            for (int j = 0; j < methods_list.Count; j++)
                            {
                                available_methods[j] = methods_list[j];
                            }
                        }
                        break;
                    case "method_bindings":
                        {
                            List<string[]> method_bindings_list = new List<string[]>();
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                method_bindings_list.Add(line.Split('~'));
                            }
                            method_bindings = new string[method_bindings_list.Count][];
                            for (int j = 0; j < method_bindings_list.Count; j++)
                            {
                                method_bindings[j] = method_bindings_list[j];
                            }
                        }
                        break;
                    case "method_acls":
                        {
                            List<string[]> method_acls_list = new List<string[]>();
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                method_acls_list.Add(line.Split('~'));
                            }
                            method_permissions = new string[method_acls_list.Count][];
                            for (int j = 0; j < method_acls_list.Count; j++)
                            {
                                method_permissions[j] = method_acls_list[j];
                            }
                        }
                        break;
                    case "column_names":
                        {
                            List<string[][]> column_names_list = new List<string[][]>();
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                string[] splitted = line.Split('~');
                                List<string[]> list_splitted = new List<string[]>();
                                foreach(string s in splitted)
                                {
                                    list_splitted.Add(s.Split('¬'));
                                }
                                string[][] array_splitted = new string[list_splitted.Count][];
                                for(int j = 0; j < list_splitted.Count; j++)
                                {
                                    array_splitted[j] = list_splitted[j];
                                }
                                column_names_list.Add(array_splitted);
                            }
                            column_names = new string[column_names_list.Count][][];
                            for (int j = 0; j < column_names_list.Count; j++)
                            {
                                column_names[j] = column_names_list[j];
                            }
                        }
                        break;
                    case "default_values":
                        {
                            List<string[][]> def_vals_list = new List<string[][]>();
                            while (true)
                            {
                                string line = reader.ReadLine();
                                if (line == null || line == "")
                                {
                                    break;
                                }
                                string[] splitted = line.Split('~');
                                List<string[]> list_splitted = new List<string[]>();
                                foreach (string s in splitted)
                                {
                                    list_splitted.Add(s.Split('¬'));
                                }
                                string[][] array_splitted = new string[list_splitted.Count][];
                                for (int j = 0; j < list_splitted.Count; j++)
                                {
                                    array_splitted[j] = list_splitted[j];
                                }
                                def_vals_list.Add(array_splitted);
                            }
                            default_values = new string[def_vals_list.Count][][];
                            for (int j = 0; j < def_vals_list.Count; j++)
                            {
                                default_values[j] = def_vals_list[j];
                            }
                        }
                        break;
                }
                reader.Close();
            }
        }
        static void WriteRootDatabase()
        {
            ClearRootDatabase();
            int root_app_index = GetAppIndex("root");
            for(int i = 0; i < database_paths[root_app_index].Length; i++)
            {
                FileStream fs = new FileStream(databases_dir + database_paths[root_app_index][i], FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                StreamWriter writer = new StreamWriter(fs);
                switch (database_names[root_app_index][i])
                {
                    case "users":
                        {
                            foreach (string[] user in root_users)
                            {
                                string entry = "";
                                for (int j = 0; j < user.Length; j++)
                                {
                                    entry += user[j];
                                    if (j != user.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;
                    case "auth_tokens":
                        {
                            foreach (string[] auth_token in root_auth_tokens)
                            {
                                string entry = "";
                                for (int j = 0; j < auth_token.Length; j++)
                                {
                                    entry += auth_token[j];
                                    if (j != auth_token.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;
                    case "apps":
                        {
                            
                            string entry = "";
                            for(int j = 0; j< apps.Length; j++)
                            {
                                entry += apps[j];
                                if(j != apps.Length - 1)
                                {
                                    entry += "~";
                                }
                            }
                            writer.WriteLine(entry);
                        }
                        break;
                    case "database_names":
                        {
                            foreach (string[] db_names in database_names)
                            {
                                string entry = "";
                                for(int j = 0; j < db_names.Length; j++)
                                {
                                    entry += db_names[j];
                                    if(j != db_names.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;
                    case "database_paths":
                        {
                            foreach (string[] db_paths in database_paths)
                            {
                                string entry = "";
                                for (int j = 0; j < db_paths.Length; j++)
                                {
                                    entry += db_paths[j];
                                    if (j != db_paths.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;
                    case "roles":
                        {
                            foreach (string[] roles_n in roles)
                            {
                                string entry = "";
                                for (int j = 0; j < roles_n.Length; j++)
                                {
                                    entry += roles_n[j];
                                    if (j != roles_n.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;
                    case "methods":
                        {
                            foreach (string[] methods in available_methods)
                            {
                                string entry = "";
                                for (int j = 0; j < methods.Length; j++)
                                {
                                    entry += methods[j];
                                    if (j != methods.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;
                    case "method_bindings":
                        {
                            foreach (string[] method_bind in method_bindings)
                            {
                                string entry = "";
                                for (int j = 0; j < method_bind.Length; j++)
                                {
                                    entry += method_bind[j];
                                    if (j != method_bind.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;

                    case "method_acls":
                        {
                            foreach (string[] methods_acls in method_permissions)
                            {
                                string entry = "";
                                for (int j = 0; j < methods_acls.Length; j++)
                                {
                                    entry += methods_acls[j];
                                    if (j != methods_acls.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;
                    case "column_names":
                        {
                            foreach (string[][] column_names_app in column_names)
                            {
                                string entry = "";

                                for (int j = 0; j < column_names_app.Length; j++)
                                {
                                    for(int k = 0; k < column_names_app[j].Length; k++)
                                    {
                                        entry += column_names_app[j][k];
                                        if(k != column_names_app[j].Length - 1)
                                        {
                                            entry += "¬";
                                        }
                                    }
                                    if(j != column_names_app.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;
                    case "default_values":
                        {
                            foreach (string[][] def_values_app in default_values)
                            {
                                string entry = "";

                                for (int j = 0; j < def_values_app.Length; j++)
                                {
                                    for (int k = 0; k < def_values_app[j].Length; k++)
                                    {
                                        entry += def_values_app[j][k];
                                        if (k != def_values_app[j].Length - 1)
                                        {
                                            entry += "¬";
                                        }
                                    }
                                    if (j != def_values_app.Length - 1)
                                    {
                                        entry += "~";
                                    }
                                }
                                writer.WriteLine(entry);
                            }
                        }
                        break;
                }
                //Console.WriteLine("Saving " + database_names[root_app_index][i]);
                writer.Close();
            }
        }
        static void ClearRootDatabase()
        {
            int app_ins = GetAppIndex("root");
            foreach (string db_path in database_paths[app_ins])
            {
                FileStream fs = new FileStream(databases_dir + db_path, FileMode.Truncate, FileAccess.ReadWrite, FileShare.ReadWrite);
                fs.Close();
            }
        }

        

        public static void CompileFile(string sourcepath, string exepath)
        {
            Process proc = new Process();
            proc.StartInfo.FileName = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe";
            proc.StartInfo.Arguments = "/t:exe /out:"+exepath+" "+sourcepath;
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.CreateNoWindow = true;
            proc.Start();
        }
        public static void LaunchBindExe(string exepath, string output_txt_path)
        {
            Process proc = new Process();
            proc.StartInfo.FileName = exepath;
            proc.StartInfo.Arguments = output_txt_path;
            proc.Start();
        }
        public static void CreateFile(string path)
        {
            new FileInfo(path).Directory.Create();
            File.Create(path).Close();
        }
        public static void WriteToFile(string path, string content)
        {
            File.WriteAllText(path, content);
        }
        public static void WriteToFile(string path, byte[] content)
        {
            File.WriteAllBytes(path, content);
        }
        public static string CreateMD5(string input)
        {
            StringBuilder hash = new StringBuilder();
            MD5CryptoServiceProvider md5provider = new MD5CryptoServiceProvider();
            byte[] bytes = md5provider.ComputeHash(new UTF8Encoding().GetBytes(input));

            for (int i = 0; i < bytes.Length; i++)
            {
                hash.Append(bytes[i].ToString("x2"));
            }
            return hash.ToString();
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