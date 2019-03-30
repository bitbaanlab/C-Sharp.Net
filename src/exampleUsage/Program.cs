using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CSharpLib
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write(" ____  _ _   ____                      __  __    _    _          _     \r\n");
            Console.Write("| __ )(_) |_| __ )  __ _  __ _ _ __   |  \\/  |  / \\  | |    __ _| |__  \r\n");
            Console.Write("|  _ \\| | __|  _ \\ / _` |/ _` | '_ \\  | |\\/| | / _ \\ | |   / _` | '_ \\ \r\n");
            Console.Write("| |_) | | |_| |_) | (_| | (_| | | | | | |  | |/ ___ \\| |__| (_| | |_) |\r\n");
            Console.Write("|____/|_|\\__|____/ \\__,_|\\__,_|_| |_| |_|  |_/_/   \\_\\_____\\__,_|_.__/ \r\n\r\n");
            string email = "", password = "", serveraddress = "";
            string file_path = "";
            Console.Write("Please insert API server address [Default=https://malab.bitbaan.com]: ");
            serveraddress = Console.ReadLine();
            if(serveraddress == "")
                serveraddress = "https://malab.bitbaan.com";
            Console.Write("Please insert email address: ");
            email = Console.ReadLine();
            Console.Write("Please insert your password: ");
            password = Console.ReadLine();
            MALabLib malab = new MALabLib(serveraddress);
            JObject returnValue = malab.login(email, password);
            if (returnValue.SelectToken("success").ToObject<bool>() == true)
                Console.Write("You are logged in successfully.\r\n");
            else
            {
                Console.Write("error code {0} occurred.\r\n", returnValue.SelectToken("error_code").ToObject<int>());
                Console.ReadLine();
                return;
            }
            Console.Write("Please enter the path of file to scan: ");
            file_path = Console.ReadLine();
            returnValue = malab.scan(file_path, Path.GetFileName(file_path));
            if (returnValue.SelectToken("success").ToObject<bool>() == true)
            {//getting scan results:
                bool is_finished = false;
                string file_hash = malab.get_sha256(file_path);
                int scan_id = returnValue.SelectToken("scan_id").ToObject<int>();
                while(is_finished == false){
                    Console.Write("Waiting for getting results...\r\n");
                    returnValue = malab.results(file_hash, scan_id);
                    if(returnValue.SelectToken("success").ToObject<bool>() == false)
                    {
                        Console.Write("error code {0} occurred.\r\n", returnValue.SelectToken("error_code").ToObject<int>());
                        Console.ReadLine();
                    }
                    Console.Clear();
                    foreach(JObject current_av_result in returnValue.SelectToken("results").ToArray())
                    {
                        if (current_av_result.SelectToken("result_state").ToObject<int>() == 32) //file Is malware
                            Console.Write("{0} ==> {1}\r\n", current_av_result.SelectToken("av_name").ToString(), current_av_result.SelectToken("virus_name").ToString());
                        else if(current_av_result.SelectToken("result_state").ToObject<int>() == 33)  //file Is clean
                            Console.Write("{0} ==> {1}\r\n", current_av_result.SelectToken("av_name").ToString(), "Clean");
                    }
                    is_finished = returnValue.SelectToken("is_finished").ToObject<bool>();
                    System.Threading.Thread.Sleep(2000);
                }
            }
            else
            {
                Console.Write("error code {0} occurred.\r\n", returnValue.SelectToken("error_code").ToObject<int>());
                Console.ReadLine();
                return;
            }
        }
    }
}
