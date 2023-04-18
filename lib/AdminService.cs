using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using System.Threading.Tasks;
using System.Net.Http;
using System;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpSCCM
{

    public static class AdminService
    {
        //This function handles the inital query to AdminService and returns the Operation Id
        public static string TriggerMethod(string Query, string CollName)
        {
            Console.WriteLine("[+] Sending query to AdminService");
            var operationId = "";
            var trustAllCerts = new TrustAllCertsPolicy();
            ServicePointManager.ServerCertificateValidationCallback = trustAllCerts.ValidateCertificate;
            var request = (HttpWebRequest)WebRequest.Create($"https://CM1/AdminService/v1.0/Collections('{CollName}')/AdminService.RunCMPivot");
            request.Method = "POST";
            request.ContentType = "application/json";
            request.UseDefaultCredentials = true;

            var json = $"{{\"InputQuery\":\"{Query}\"}}";

            var data = System.Text.Encoding.UTF8.GetBytes(json);
            using (var stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }

            var response = (HttpWebResponse)request.GetResponse();
            using (var streamReader = new StreamReader(response.GetResponseStream()))
            {

                var jsonResponse = streamReader.ReadToEnd();
                var jsonObject = JsonConvert.DeserializeObject<JsonResponse>(jsonResponse);
                operationId = jsonObject.OperationId;
                System.Diagnostics.Debug.WriteLine(operationId);
            }
            //After sending the query we gather the Operation Id for next steps -> Gather operation results
            return operationId;
        }
        
        //This functions will periodically check the response status we get when looking for operation completition
        //It will make 5 attempts before exiting
        public static async Task<string> CheckStatusAsync(string inpt2, string CollName)

        {
            var opId = TriggerMethod(inpt2, CollName);
            var clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
            clientHandler.UseDefaultCredentials = true;

            //This is the request made to adminService checking for operation results
            var client = new HttpClient(clientHandler);
            var url = $"https://CM1/AdminService/v1.0/Collections('{CollName}')/AdminService.CMPivotResult(OperationId={opId})";
            var status = 0;
            System.Diagnostics.Debug.WriteLine(status);
            HttpResponseMessage response = null;

            int counter = 0;
            
            //Here we try to stop the function that retrieves results from Rest API to loop infinitely by placing a cap after 5 attempts
            while (status != 200 && counter < 5)
            {
                response = await client.GetAsync(url);
                status = (int)response.StatusCode;

                if (status != 200)
                {
                    counter++;
                    Console.WriteLine($"[+] Attempt {counter}: Checking for query operation to completition");
                    await Task.Delay(TimeSpan.FromSeconds(7));
                }
            }

            if (status == 200)
            {   
                //Success message after retrieving operation results data
                Console.WriteLine("[+] Successfuly retrieved results from AdminService");
            }
            else
            {   //Failure message
                System.Diagnostics.Debug.WriteLine("[!] Failed to get a response from REST API after 5 attempts");
            }


            var reqBody = await response.Content.ReadAsStringAsync();
            var jsonBody = reqBody.Replace("\\r\\n\\r\\n", Environment.NewLine);
            var jsonObject = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(jsonBody);
            var result = jsonObject["value"][0]["Result"];
            var output = new StringBuilder();

            foreach (var item in result)
            {
                // Would like to change this for some other word that describes this is an element of the output received describing one row of results. 
                // Hard to encapsulate all the data we can get with CMPivot though
                output.AppendLine("\r\n\r\n\r\n---------------- Result ------------------");

                // Here we start parsing the JSON to display it in a command line and make as readabla as possible
                foreach (JProperty property in item.Children())
                {
                    output.AppendLine();
                    int numSpaces = 30 - property.Name.Length;
                    string pad1 = new string(' ', numSpaces);

                    output.Append(property.Name + pad1 + ": ");

                    //When testing against Windows EventLog queries. There is a very long string which contains some nested
                    //JSON-like key:value pairs mixed with some regular strings. This was difficult to parse but here
                    //follows my attempt at making presentable

                    if (property.Value is JValue jValue)
                    {
                        if (jValue.Type == JTokenType.String && jValue.ToString().Contains(Environment.NewLine))
                        {
                            output.AppendLine();
                            
                            //Separating actual JSON from strings that contain mix of key:value pairs and single strings
                            
                            string[] lines = jValue.ToString().Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

                            for (int i = 0; i < lines.Length; i++)
                            {
                                string _line = lines[i];
                                string pattern = @".*?:[A-Za-z0-9-]*";

                                if (!Regex.IsMatch(_line, pattern))
                                {
                                    output.AppendLine();
                                } 

                            string[] line_string = lines[i].Split(':');

                                if (line_string.Length > 1)
                                {
                                    for (int x = 0; x < line_string.Length - 1; x += 2)
                                    {
                                        int lineNumSpaces = 30 - line_string[x].Length;
                                        string pad2 = new string(' ', Math.Max(0, lineNumSpaces));
                                        int lineNumSpaces2 = 15;
                                        string pad3 = new string(' ', Math.Max(0, lineNumSpaces2));

                                        if (x + 1 < line_string.Length)
                                        {
                                            output.AppendLine(pad3 + line_string[x] + pad2 + ": " + line_string[x + 1]);
                                        }
                                        else
                                        {
                                            output.AppendLine(line_string[x] + pad2 + ": [empty]");
                                        }
                                    }
                                }
                                else
                                {
                                    output.AppendLine(lines[i]);
                                }
                            }
                        }
                        else
                        {
                            output.AppendLine(jValue.ToString());
                        }
                    }
                }   output.AppendLine("--------------------------------------------");
            }
            return output.ToString();
        }

        // Entry point with arguments provided by user or defaults from command handler
        public static async Task Main(string inpt3, string CollName)
        {   
            var status = await CheckStatusAsync(inpt3, CollName);
            System.Diagnostics.Debug.WriteLine(status);
            Console.WriteLine("\r\n\r\n Received Data:" + status);

        }

    }
    public class JsonResponse
    {
        public string OperationId { get; set; }
    }
    public class TrustAllCertsPolicy
    {
        public bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}
