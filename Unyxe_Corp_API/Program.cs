using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Drawing;
using System.Security.Permissions;
using static System.Net.Mime.MediaTypeNames;

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

        static string home_dir = @"D:\UnyxeCorpAPI\";

        static string databases_dir = home_dir + @"Databases\";

        static string[] apps = { "chores" };
        static string[][] database_names =
        {
            new string[] {"users", "auth_tokens", "chores"}
        };
        static string[][] database_paths =
        {
            new string[] {@"ChoresAPP\us.db", @"ChoresAPP\au.db", @"ChoresAPP\ch.db"}
        };
        static string[][] roles =
        {
            new string[] { "Admin", "User", "Anonymous" }
        };
        static string[][][] column_names =
        {
            //APP: chores
            new string[][]
            {
                new string[] { "username", "password", "role"},
                new string[] { "username", "auth_token"},
                new string[] { "username_sender", "usewrname_reciever", "chore_type", "chore_desc", "done_it"},
            }
        };
        static string[][] available_methods =
        {
            new string[] { "sign", "log"}
        };
        static string[][] method_permissions =
        {
            new string[]{ "0:2", "0:2" },
        };

        static List<string[]>[][] databases = new List<string[]>[apps.Length][];








        public static void Main()
        {
            InitRAMDatabases();
            ReadDataFromDatabase();
            DisplayRAMDatabaseStructure();
            Console.WriteLine(GetLocalIPAddress());
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Listen1();
        }


        private static void Send(string str, Socket clientSocket)
        {
            try
            {
                string string_http = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 25\r\nBODY_tw: " + ToBase64(str) + "\r\n\r\nHello, thats my webserver";

                byte[] buffer = Encoding.ASCII.GetBytes(string_http);
                clientSocket.Send(buffer);
                clientSocket.Close();
                Console.WriteLine("[=>]" + string_http);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Sending error: " + ex.Message);
                Console.WriteLine("IP is offline");
            }
        }

        private static void Listen1()
        {
            listenThread = new Thread(new ThreadStart(Listen));
            listenThread.Start();
        }

        private static void Listen()
        {
            try
            {
                ip2 = IPAddress.Parse(GetLocalIPAddress());
                endPoint2 = new IPEndPoint(ip2, 8080);
                socket.Bind(endPoint2);
                socket.Listen(100);
                while (true)
                {
                    Socket clientSocket = socket.Accept();
                    byte[] buffer = new byte[65536];
                    int bytesReceived = clientSocket.Receive(buffer);
                    string message = Encoding.ASCII.GetString(buffer, 0, bytesReceived);
                    last_msg = message;
                    Console.WriteLine("[" + clientSocket.RemoteEndPoint.ToString() + "]" + message);
                    //Send("Hello", clientSocket);
                    string m = "";
                    bool write_ = false;
                    foreach (char c in message)
                    {
                        if (write_)
                        {
                            if (c == ' ')
                            {
                                break;
                            }
                            m += c;
                        }
                        if (c == ' ')
                        {
                            write_ = true;
                        }
                    }
                    try
                    {
                        message = FromBase64(m.Substring(1, m.Length - 1));
                    }
                    catch { continue; }
                    Console.WriteLine("|" + message + "|");

                    try
                    {

                        string[] app_parse = ParseForApp(message);
                        message = app_parse[1];
                        string app = app_parse[0];
                        string[] args = ParseMessage(message, app);

                        string ipad = "";
                        string endp_str = clientSocket.RemoteEndPoint.ToString();
                        for (int i = 0; i < endp_str.Length; i++)
                        {
                            if (endp_str[i] == ':')
                            {
                                break;
                            }
                            ipad += endp_str[i];
                        }
                        IPAddress ipaddr = IPAddress.Parse(ipad);
                        Socket endp = clientSocket;
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
                                string success_doing_method = DoMethod(args[2], app, args[3], endp);
                                if (success_doing_method == "success")
                                {
                                    if (args[2] == "sign" || args[2] == "tweet")
                                    {
                                        Send("Success!", endp);
                                    }

                                    //Console.WriteLine(auth_tokens.Count);
                                }
                                else
                                {
                                    Send("Failed! Reason: " + success_doing_method, endp);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Send("Failed! Server error occured!", endp);
                        }
                        WriteDataToDatabase();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Error occured, while trying to parse the message");
                    }

                    clientSocket.Close();

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Listening error: " + ex.Message);
                Main();
            }

        }
        public static string DoMethod(string method, string app, string arguments_raw, Socket user_endp)
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



            //Main DoMethod Part
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

                        if (!apps.Contains(app))
                        {
                            method_success = "app_is_not_found";
                            return method_success;
                        }

                        if (CheckPermission(auth_token, method, app))
                        {
                            method_success = SignIn(username, password, app);
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



                        if (!apps.Contains(app))
                        {
                            method_success = "app_is_not_found";
                            return method_success;
                        }

                        if (CheckPermission(auth_token, method, app))
                        {
                            method_success = LogIn(username, password, app);
                            if (method_success == "success")
                            {
                                Send("Auth token: " + GetUserAuthToken(username, app), user_endp);
                            }
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }

                        return method_success;
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
                if (message[i] == '\\')
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
                success_parse = "method_not_available";
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


        static string LogIn(string username, string password, string app)
        {
            string success_login = "success";
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "users");
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
        static string SignIn(string username, string password, string app)
        {
            string success_signin = "success";
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "users");
            if (CheckUserPresence(username, app))
            {
                success_signin = "username_already_present";
                return success_signin;
            }
            databases[app_index][db_index].Add(new string[] { username, password, "User", "false" });
            return success_signin;
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
        static bool CheckPermission(string auth_token, string method, string app)
        {
            string role;
            int app_index = GetAppIndex(app);
            int db_index = GetDatabaseIndex(app, "users");
            if (auth_token == "")
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
            foreach (string role_test in method_permission)
            {
                if (role_index == Int32.Parse(role_test))
                {
                    return true;
                }
            }
            return false;

        }

        static void ClearDatabases()
        {
            foreach (string[] app_dbs in database_paths)
            {
                foreach (string db_path in app_dbs)
                {
                    FileStream fs = new FileStream(databases_dir + db_path, FileMode.Truncate, FileAccess.ReadWrite, FileShare.ReadWrite);
                    fs.Close();
                }
            }
        }
        static void WriteDataToDatabase()
        {
            ClearDatabases();
            int inc_app = 0;
            foreach (string[] app_dbs in database_paths)
            {
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
        static void ClearRAMDatabases()
        {
            for (int i = 0; i < apps.Length; i++)
            {
                for (int j = 0; j < database_names[i].Length; j++)
                {
                    databases[i][j].Clear();
                }
            }
        }
        static void InitRAMDatabases()
        {
            for (int i = 0; i < apps.Length; i++)
            {
                databases[i] = new List<string[]>[database_names[i].Length];
                for (int j = 0; j < database_names[i].Length; j++)
                {
                    databases[i][j] = new List<string[]>();
                }
            }
        }
        static void DisplayRAMDatabaseStructure()
        {
            for (int i = 0; i < apps.Length; i++)
            {
                Console.WriteLine("-" + apps[i]);
                for (int j = 0; j < database_names[i].Length; j++)
                {
                    Console.WriteLine("----" + database_names[i][j]);
                    for (int k = 0; k < databases[i][j].Count; k++)
                    {
                        string[] entry = databases[i][j][k];
                        Console.Write("-------");
                        for (int l = 0; l < entry.Length; l++)
                        {
                            Console.Write(column_names[i][j][l] + ":" + entry[l]);
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
        static void ReadDataFromDatabase()
        {
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
                    inc_db++;
                }
                inc_app++;
            }
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