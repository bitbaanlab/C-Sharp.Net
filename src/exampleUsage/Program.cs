using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;

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
            Console.Write("Please insert API server address [Default=https://apimalab.bitbaan.com]: ");
            serveraddress = Console.ReadLine();
            if(serveraddress == "")
                serveraddress = "https://apimalab.bitbaan.com";
            Console.Write("Please insert email address: ");
            email = Console.ReadLine();
            Console.Write("Please insert your password: ");
            password = Console.ReadLine();
            MALabLib malab = new MALabLib(serveraddress);
            JObject params1 = new JObject();
            params1.Add("email", email);
            params1.Add("password", password);
            JObject return_value = malab.call_with_json_input("user/login", params1);
            if (return_value.SelectToken("success").ToObject<bool>() == true)
                Console.Write("You are logged in successfully.\r\n");
            else
            {
                Console.Write(malab.get_error(return_value));
                Console.ReadLine();
                return;
            }
            Console.Write("Please enter the path of file to scan: ");
            file_path = Console.ReadLine();
            string file_name = Path.GetFileName(file_path);
            string apikey = return_value.SelectToken("apikey").ToObject<string>();
            JObject params2 = new JObject();
            params2.Add("file_name", file_name);
            params2.Add("apikey", apikey);
            return_value = malab.call_with_form_input("file/scan", params2, "file_data", file_path);
            if (return_value.SelectToken("success").ToObject<bool>() == true){ //getting scan results:
                bool is_finished = false;
                string file_hash = malab.get_sha256(file_path);
                int scan_id = return_value.SelectToken("scan_id").ToObject<int>();
                while(is_finished == false){
                    Console.Write("Waiting for getting results...\r\n");
                    JObject params3 = new JObject();
                    params3.Add("hash", file_hash);
                    params3.Add("apikey", apikey);
                    return_value = malab.call_with_json_input("file/scan/result/get", params3);
                    if (return_value.SelectToken("success").ToObject<bool>() == false)
                    {
                        Console.Write(malab.get_error(return_value));
                        Console.ReadLine();
                    }
                    Console.Clear();
                    foreach(JObject current_av_result in return_value.SelectToken("scan").SelectToken("results").ToArray())
                    {
                        if (current_av_result.SelectToken("result").ToObject<string>() == "malware") //file Is malware
                            Console.Write("{0} ==> {1}\r\n", current_av_result.SelectToken("av_name").ToString(), current_av_result.SelectToken("malware_name").ToString());
                        else if(current_av_result.SelectToken("result").ToObject<string>() == "clean")  //file Is clean
                            Console.Write("{0} ==> {1}\r\n", current_av_result.SelectToken("av_name").ToString(), "Clean");
                    }
                    is_finished = return_value.SelectToken("scan").SelectToken("is_finished").ToObject<bool>();
                    System.Threading.Thread.Sleep(2000);
                }
            }
            else
                Console.Write(malab.get_error(return_value));
            Console.ReadLine();
        }
    }
}
