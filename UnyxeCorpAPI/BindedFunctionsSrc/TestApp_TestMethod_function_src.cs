using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HelloWorldApp
{
    internal class Program
    {
        static string output_txt_path = "";
        static void Main(string[] args)
        {
            try
            {
                output_txt_path = args[0];
                OutputTextCheck();
                MainFunction();
            }
            catch { Output(" ", "Failed!"); }
        }

        static void OutputTextCheck()
        {
            if (!File.Exists(output_txt_path))
            {
                File.Create(output_txt_path).Close();
            }
        }
        static void Output(string text, string status)
        {
            FileStream fs = new FileStream(output_txt_path, FileMode.Truncate, FileAccess.ReadWrite, FileShare.ReadWrite);
            fs.Close();
            File.WriteAllText(output_txt_path,status + "\n" + text);
        }

        static void MainFunction()
        {
            Output("Hello world!", "Done!");
        }
    }
}
