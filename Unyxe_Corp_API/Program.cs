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
using System.Drawing.Drawing2D;
using System.Security.Permissions;

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

        static string[] available_methods = { "tweet", "sign", "log", "listus", "infou", "editus", "gettweets", "infouser", "getprofpic", "getbanner" };
        static string[] roles = { "Admin", "User", "Anonymous" };
        static string[] user_attributes = { "username", "password", "role", "twitter-red" };
        static string[] method_permissions = { "0:1", "0:2", "0:2", "0", "0", "0", "0:1", "0:1", "0:1", "0:1" };

        static List<string[]> users = new List<string[]>();
        static List<string[]> auth_tokens = new List<string[]>();
        static List<string[]> tweets = new List<string[]>();

        static string database_users_path = @"D:\TwitterProject\Twi'eh Project\Database\us.db";
        static string database_authtokens_path = @"D:\TwitterProject\Twi'eh Project\Database\au.db";
        static string database_tweets_path = @"D:\TwitterProject\Twi'eh Project\Database\tw.db";


        static string profile_pics_paths = @"D:\TwitterProject\Twi'eh Project\Images\ProfilePics\";
        static string banners_paths = @"D:\TwitterProject\Twi'eh Project\Images\Banners\";

        static int max_packet_l = 40000;


        public static void Main()
        {
            if (!File.Exists(database_users_path))
            {
                database_users_path = @"S:\computer science\TW\us.db";
                database_authtokens_path = @"S:\computer science\TW\au.db";
                database_tweets_path = @"S:\computer science\TW\tw.db";
            }
            ReadDataFromDatabase();
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
        private static void SendPicture(string path_to_pic, int packet_number, Socket clientSocket)
        {
            if (!File.Exists(path_to_pic))
            {
                path_to_pic = profile_pics_paths + "default_icon.png";
            }
            string zipped_image = ToBase64FromByte(ImageToByte(Image.FromFile(path_to_pic)));
            int num_of_packets = zipped_image.Length / max_packet_l + 1;
            if (packet_number == 0)
            {
                Send("MP_" + num_of_packets, clientSocket);
                return;
            }
            string piece = "";
            int act_i = 0;
            bool has_sent = false;
            for (int i = 0; i < zipped_image.Length; i++)
            {
                piece += zipped_image[i];
                if (i % max_packet_l == 0 && i != 0)
                {
                    if (act_i == packet_number - 2)
                    {
                        Send("CON_" + piece, clientSocket);
                        has_sent = true;
                        break;
                    }
                    piece = "";
                    act_i++;
                }
            }

            if (packet_number == 1)
            {
                Send("EMP_" + (act_i + 1), clientSocket);
                return;
            }
            if (!has_sent)
            {
                Send("CON_" + piece, clientSocket);
            }
        }

        private static void SendBanner(string path_to_pic, int packet_number, Socket clientSocket)
        {
            Console.WriteLine(path_to_pic);
            if (!File.Exists(path_to_pic))
            {
                path_to_pic = banners_paths + "default_banner.png";
            }
            string zipped_image = ToBase64FromByte(ImageToByte(Image.FromFile(path_to_pic)));
            int num_of_packets = zipped_image.Length / max_packet_l + 1;
            if (packet_number == 0)
            {
                Send("MP_" + num_of_packets, clientSocket);
                return;
            }
            string piece = "";
            int act_i = 0;
            bool has_sent = false;
            for (int i = 0; i < zipped_image.Length; i++)
            {
                piece += zipped_image[i];
                if (i % max_packet_l == 0 && i != 0)
                {
                    if (act_i == packet_number - 2)
                    {
                        Send("CON_" + piece, clientSocket);
                        has_sent = true;
                        break;
                    }
                    piece = "";
                    act_i++;
                }
            }

            if (packet_number == 1)
            {
                Send("EMP_" + (act_i + 1), clientSocket);
                return;
            }
            if (!has_sent)
            {
                Send("CON_" + piece, clientSocket);
            }
        }

        public static byte[] ImageToByte(Image img)
        {
            ImageConverter converter = new ImageConverter();
            return (byte[])converter.ConvertTo(img, typeof(byte[]));
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
                endPoint2 = new IPEndPoint(ip2, 80);
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
                        string[] args = ParseMessage(message);

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
                                string success_doing_method = DoMethod(args[2], args[3], endp);
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
        public static string DoMethod(string method, string arguments_raw, Socket user_endp)
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
                        if (CheckPermission(auth_token, method))
                        {
                            method_success = SignIn(username, password);
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
                        if (CheckPermission(auth_token, method))
                        {
                            method_success = LogIn(username, password);
                            if (method_success == "success")
                            {
                                Send("Auth token: " + GetUserAuthToken(username), user_endp);
                            }
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }

                        return method_success;
                    }
                case "tweet":
                    {
                        string message;
                        string auth_token = "";
                        int index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "message")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found == -1)
                        {
                            method_success = "message_not_provided";
                            return method_success;
                        }
                        message = arg_values[index_found];
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
                        if (CheckPermission(auth_token, method))
                        {
                            method_success = SendTweet(message, auth_token);
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }
                        return method_success;
                    }
                case "gettweets":
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
                        if (CheckPermission(auth_token, method))
                        {
                            method_success = "success";
                            if (method_success == "success")
                            {
                                List<string[]> tweets_ = GetTweetsForUsername(auth_token);
                                string zipped_tweets = "TWE";
                                foreach (string[] tweet in tweets_)
                                {
                                    zipped_tweets += "{" + tweet[0] + "`" + tweet[1] + "`" + tweet[2] + "}";

                                }
                                Send(zipped_tweets, user_endp);

                            }
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }
                        return method_success;
                    }

                case "listus":
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
                        if (CheckPermission(auth_token, method))
                        {
                            method_success = "success";
                            Send("Listing users: ", user_endp);
                            foreach (string[] user in users)
                            {
                                Send(user[0], user_endp);
                            }
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }
                        return method_success;
                    }
                case "infou":
                    {
                        string auth_token = "";
                        string username = "";

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
                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "username")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            username = arg_values[index_found];
                        }
                        else
                        {
                            method_success = "username_is_not_provided";
                            return method_success;
                        }
                        if (CheckPermission(auth_token, method))
                        {
                            method_success = "success";
                            Send("User info: ", user_endp);
                            string[] user = users[GetUserID(username)];
                            Send("Username: " + user[0], user_endp);
                            Send("Password: " + user[1], user_endp);
                            Send("Role: " + user[2], user_endp);
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }
                        return method_success;
                    }
                case "infouser":
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

                        if (CheckPermission(auth_token, method))
                        {
                            method_success = "success";
                            string msg = "INFO{";
                            string[] user = users[GetUserID(GetUserByToken(auth_token))];
                            for (int i = 0; i < user.Length; i++)
                            {
                                msg += $"{user[i]}";
                                if (i == user.Length - 1)
                                {
                                    msg += "}";
                                }
                                else
                                {
                                    msg += "`";
                                }
                            }
                            Send(msg, user_endp);
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }
                    }
                    return method_success;
                case "getprofpic":
                    {
                        string auth_token = "";
                        string username = "";
                        string p_num = "";

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
                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "username")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            username = arg_values[index_found];
                        }
                        else
                        {
                            method_success = "username_is_not_provided";
                            return method_success;
                        }
                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "num")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            p_num = arg_values[index_found];
                        }
                        else
                        {
                            method_success = "packet_number_is_not_provided";
                            return method_success;
                        }
                        if (CheckPermission(auth_token, method))
                        {
                            method_success = "success";
                            SendPicture(profile_pics_paths + username + "_icon.png", Int32.Parse(p_num), user_endp);
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }

                    }
                    return method_success;
                case "getbanner":
                    {
                        string auth_token = "";
                        string username = "";
                        string p_num = "";

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
                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "username")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            username = arg_values[index_found];
                        }
                        else
                        {
                            method_success = "username_is_not_provided";
                            return method_success;
                        }
                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "num")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            p_num = arg_values[index_found];
                        }
                        else
                        {
                            method_success = "packet_number_is_not_provided";
                            return method_success;
                        }
                        if (CheckPermission(auth_token, method))
                        {
                            method_success = "success";
                            SendBanner(banners_paths + username + "_banner.png", Int32.Parse(p_num), user_endp);
                        }
                        else
                        {
                            method_success = "operation_not_permitted";
                        }

                    }
                    return method_success;
                case "editus":
                    {
                        string auth_token = "";
                        string username = "";
                        string attribute = "";
                        string new_value = "";

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
                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "username")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            username = arg_values[index_found];
                        }
                        else
                        {
                            method_success = "username_is_not_provided";
                            return method_success;
                        }
                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "attribute")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            attribute = arg_values[index_found];
                        }
                        else
                        {
                            method_success = "attribute_is_not_provided";
                            return method_success;
                        }
                        index_found = -1;
                        for (int i = 0; i < arg_names.Count; i++)
                        {
                            if (arg_names[i] == "newvalue")
                            {
                                index_found = i;
                                break;
                            }
                        }
                        if (index_found != -1)
                        {
                            new_value = arg_values[index_found];
                        }
                        else
                        {
                            method_success = "newvalue_is_not_provided";
                            return method_success;
                        }
                        if (CheckPermission(auth_token, method))
                        {
                            method_success = ChangeUserAttribute(username, attribute, new_value);
                            return method_success;
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
        public static List<string[]> GetTweetsForUsername(string auth_token)
        {
            List<string[]> emails_sent = new List<string[]>();
            string username = GetUserByToken(auth_token);
            foreach (string[] email in tweets)
            {
                if (true)
                {
                    emails_sent.Add(email);
                }
            }
            return emails_sent;
        }
        public static string SendTweet(string message, string auth_token)
        {
            string method_success = "success";
            string username_from = GetUserByToken(auth_token);
            string date = DateTime.Now.ToString("dd/MM/yyyy");
            string[] email = { username_from, message, date };
            tweets.Add(email);
            return method_success;
        }
        public static string ChangeUserAttribute(string username, string attribute, string newvalue)
        {
            string method_success = "success";
            int index_d = 0;
            bool found = false;
            //Console.WriteLine(attribute);
            foreach (string n in user_attributes)
            {
                //Console.WriteLine(n);
                if (n == attribute)
                {

                    found = true;
                    break;
                }
                index_d++;
            }
            if (!found)
            {
                method_success = "attribute_is_invalid";
                return method_success;
            }
            if (!CheckUserPresence(username))
            {
                method_success = "username_is_not_present";
                return method_success;
            }
            users[GetUserID(username)][index_d] = newvalue;
            return method_success;
        }
        public static string[] ParseMessage(string message)
        {
            string[] args = new string[4];
            string method = "";
            string port = "";
            bool is_method_section = false;
            bool is_port_section = false;
            string success_parse = "success";
            string message_body = "";
            //Parsing
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
            else if (!available_methods.Contains(method))
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


        static string LogIn(string username, string password)
        {
            string success_login = "success";
            if (!CheckUserPresence(username))
            {
                success_login = "username_not_found";
                return success_login;
            }
            if (users[GetUserID(username)][1] != password)
            {
                success_login = "password_incorrect";
                return success_login;
            }

            return success_login;
        }
        static string SignIn(string username, string password)
        {
            string success_signin = "success";
            if (CheckUserPresence(username))
            {
                success_signin = "username_already_present";
                return success_signin;
            }
            users.Add(new string[] { username, password, "User", "false" });
            return success_signin;
        }
        static string GetUserAuthToken(string username)
        {
            string auth_token;
            if (CheckAuthTokenPresence(username))
            {
                auth_token = auth_tokens[GetUserToken(username)][1];
            }
            else
            {
                auth_token = CreateMD5(users[GetUserID(username)][1] + rand.Next());
                auth_tokens.Add(new string[] { username, auth_token });
            }
            return auth_token;
        }
        static bool CheckAuthTokenPresence(string username)
        {
            foreach (string[] user in auth_tokens)
            {
                if (user[0] == username)
                {
                    return true;
                }
            }
            return false;
        }
        static bool CheckAuthTokenPresenceByToken(string token)
        {
            foreach (string[] user in auth_tokens)
            {
                if (user[1] == token)
                {
                    return true;
                }
            }
            return false;
        }
        static int GetUserToken(string username)
        {
            int index = 0;
            foreach (string[] user in auth_tokens)
            {
                if (user[0] == username)
                {
                    return index;
                }
                index++;
            }
            return -1;
        }
        static int GetUserTokenByToken(string token)
        {
            int index = 0;
            foreach (string[] user in auth_tokens)
            {
                if (user[1] == token)
                {
                    return index;
                }
                index++;
            }
            return -1;
        }
        static string GetUserByToken(string token)
        {
            string username = "";
            if (CheckAuthTokenPresenceByToken(token))
            {
                username = auth_tokens[GetUserTokenByToken(token)][0];
            }
            return username;
        }
        static bool CheckUserPresence(string username)
        {
            foreach (string[] user in users)
            {
                if (user[0] == username)
                {
                    return true;
                }
            }
            return false;
        }
        static int GetUserID(string username)
        {
            int index = 0;
            foreach (string[] user in users)
            {
                if (user[0] == username)
                {
                    return index;
                }
                index++;
            }
            return -1;
        }
        static bool CheckPermission(string auth_token, string method)
        {
            string role;
            if (auth_token == "")
            {
                role = "Anonymous";
            }
            else if (CheckAuthTokenPresenceByToken(auth_token))
            {
                role = users[GetUserID(GetUserByToken(auth_token))][2];
            }
            else
            {
                role = "Anonymous";
            }
            int role_index = 0;
            foreach (string r in roles)
            {
                if (role == r)
                {
                    break;
                }
                role_index++;
            }
            int method_index = 0;
            foreach (string r in available_methods)
            {
                if (method == r)
                {
                    break;
                }
                method_index++;
            }
            string[] method_permission = method_permissions[method_index].Split(':');
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

            FileStream fs = new FileStream(database_users_path, FileMode.Truncate, FileAccess.ReadWrite, FileShare.ReadWrite);
            fs.Close();
            fs = new FileStream(database_authtokens_path, FileMode.Truncate, FileAccess.ReadWrite, FileShare.ReadWrite);
            fs.Close();
            fs = new FileStream(database_tweets_path, FileMode.Truncate, FileAccess.ReadWrite, FileShare.ReadWrite);
            fs.Close();
        }
        static void WriteDataToDatabase()
        {
            ClearDatabases();
            FileStream fs = new FileStream(database_users_path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            StreamWriter writer = new StreamWriter(fs);
            foreach (string[] user in users)
            {
                string line_u = "";
                for (int i = 0; i < user.Length; i++)
                {
                    line_u += user[i];
                    if (i == user.Length - 1)
                    {
                        break;
                    }
                    line_u += "~";
                }
                writer.WriteLine(line_u);
            }
            writer.Close();

            fs = new FileStream(database_authtokens_path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            writer = new StreamWriter(fs);
            foreach (string[] token in auth_tokens)
            {
                string line_u = "";
                for (int i = 0; i < token.Length; i++)
                {
                    line_u += token[i];
                    if (i == token.Length - 1)
                    {
                        break;
                    }
                    line_u += "~";
                }
                writer.WriteLine(line_u);
            }
            writer.Close();

            fs = new FileStream(database_tweets_path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            writer = new StreamWriter(fs);
            foreach (string[] email in tweets)
            {
                string line_u = "";
                for (int i = 0; i < email.Length; i++)
                {
                    line_u += email[i];
                    if (i == email.Length - 1)
                    {
                        break;
                    }
                    line_u += "~";
                }
                writer.WriteLine(line_u);
            }
            writer.Close();
        }
        static void ReadDataFromDatabase()
        {
            users.Clear();
            auth_tokens.Clear();
            tweets.Clear();
            FileStream fs = new FileStream(database_users_path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            StreamReader reader = new StreamReader(fs);
            while (true)
            {
                string line = reader.ReadLine();
                if (line == null || line == "")
                {
                    break;
                }
                string[] param = line.Split('~');
                users.Add(param);
            }

            fs = new FileStream(database_authtokens_path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            reader = new StreamReader(fs);
            while (true)
            {
                string line = reader.ReadLine();
                if (line == null || line == "")
                {
                    break;
                }
                string[] param = line.Split('~');
                auth_tokens.Add(param);
            }

            fs = new FileStream(database_tweets_path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            reader = new StreamReader(fs);
            while (true)
            {
                string line = reader.ReadLine();
                if (line == null || line == "")
                {
                    break;
                }
                string[] param = line.Split('~');
                tweets.Add(param);
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