using System;
using System.Text;
using System.IO;
using System.Net;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;

namespace SharpSCCM
{

    public static class AdminService
    {
        //This function handles the inital query to AdminService and returns the Operation Id
        public static string TriggerAdminServiceQuery(string managementPoint, string query, string collectionName, string deviceId)
        {

            Console.WriteLine("[+] Sending query to AdminService");
            var operationId = "";
            var trustAllCerts = new TrustAllCertsPolicy();
            ServicePointManager.ServerCertificateValidationCallback = trustAllCerts.ValidateCertificate;
            string url = null;

            //Prepare query url based on target
            if (deviceId != null)
            {
                url = $"https://{managementPoint}/AdminService/v1.0/Device({deviceId})/AdminService.RunCMPivot";
            }
            else if (collectionName != null)
            {
                url = $"https://{managementPoint}/AdminService/v1.0/Collections('{collectionName}')/AdminService.RunCMPivot";
            }

            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.UseDefaultCredentials = true;
            var json = $"{{\"InputQuery\":\"{query}\"}}";
            var data = System.Text.Encoding.UTF8.GetBytes(json);
            
            //Extracting the OperationId from the response for future use
            using (var stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }
            var response = (HttpWebResponse)request.GetResponse();
            using (var streamReader = new StreamReader(response.GetResponseStream()))
            {
                var jsonResponse = streamReader.ReadToEnd();
                var jsonObject = JsonConvert.DeserializeObject<JObject>(jsonResponse);
                var regex = new Regex("\"OperationId\":\\s*\\d+");
                var match = regex.Match(jsonObject.ToString());

                if (match.Success)
                {
                    var operationIdString = match.Value;
                    operationId = int.Parse(Regex.Match(operationIdString, "\\d+").Value).ToString();
                }
                else
                {
                    Console.WriteLine("[!] An operation id was not found in the response received");
                }
            } 
            return operationId;
        }


     //This functions will periodically check the response status we get when looking for operation completition
     //It will make 5 attempts before exiting this value might need to be modified when working on larger environments
    public static async Task<string> CheckOperationStatusAsync(string managementPoint, string query, string collectionName, string deviceId)

        {
            var opId = TriggerAdminServiceQuery(managementPoint, query, collectionName, deviceId);
            string url = null;

            //Prepare result url based on target
            if (deviceId != null)
            {
                url = $"https://{managementPoint}/AdminService/v1.0/Device({deviceId})/AdminService.CMPivotResult(OperationId={opId})";
            }
            else if (collectionName != null)
            {
                url = $"https://{managementPoint}/AdminService/v1.0/Collections('{collectionName}')/AdminService.CMPivotResult(OperationId={opId})";
            }
        
            var clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
            clientHandler.UseDefaultCredentials = true;

            //This is the request made to adminService checking for operation results
            int counter = 0;
            var status = 0;
            var client = new HttpClient(clientHandler);
            HttpResponseMessage response = null;

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
                Console.WriteLine("[!] Failed to get a response from REST API after 5 attempts");
            }

            //Here we start deserializing the received JSON
            var reqBody = await response.Content.ReadAsStringAsync();
            var jsonBody = reqBody.Replace("\\r\\n\\r\\n", Environment.NewLine);
            var jsonObject = JsonConvert.DeserializeObject<JToken>(jsonBody);
            
            //This section deals with the variation in nesting between single device queries and collection queries
            JToken result1 = null;
            JObject jsonObject2 = JObject.Parse(reqBody);
            int resultIndex = -1; // if "Result" property not found

            //Find "Result" within dictionary
            foreach (JToken token in jsonObject2.Descendants())
            {
                if (token.Type == JTokenType.Property && ((JProperty)token).Name == "Result")
                {
                    JContainer parent = token.Parent;
                    if (parent is JObject)
                    {
                        resultIndex = ((JObject)parent).Properties().ToList().IndexOf((JProperty)token);
                        result1 = ((JProperty)token).Value;
                    }
                    else if (parent is JArray)
                    {
                        resultIndex = ((JArray)parent).IndexOf(token);
                    }
                    break;
                }
            }

            var output = new StringBuilder();
            int counter2 = 1;
            
            // Here we start parsing the JSON to display it in a command line and make as readable as possible
            foreach (var item in result1)
            {
                output.AppendLine(string.Format("\r\n\r\n\r\n---------------- CMPivot data #{0} ------------------", counter2));
                counter2++;
                
                foreach (JProperty property in item.Children())
                {
                    output.AppendLine();
                    int numSpaces = 30 - property.Name.Length;
                    string pad1 = new string(' ', numSpaces);
                    output.Append(property.Name + pad1 + ": ");

                    //When testing against Windows EventLog queries. The EventLog message contains very long string which contains a mix of nested
                    //Json-like key:value pairs and some regular strings. This was difficult to parse but here follows my attempt at making it presentable in a commandline
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

                                //Here we assign padding/indentation according to nesting level
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
        public static async Task Main(string managementPoint, string query, string collectionName, string deviceId)
        {
            var CMPdata = await CheckOperationStatusAsync(managementPoint, query, collectionName, deviceId);
            Console.WriteLine("\r\n\r\n Received Data: " + CMPdata);
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
