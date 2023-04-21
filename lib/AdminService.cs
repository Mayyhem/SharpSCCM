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
using Microsoft.ConfigurationManagement.Messaging.StatusMessages;

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

            try
            {
                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                HttpWebResponse response = null;
                using (response = (HttpWebResponse)request.GetResponse())
                {
                    var statusCode = response.StatusCode;
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
                            Console.WriteLine($"[+] OperationId: {operationId}");
                        }
                        else
                        {
                            Console.WriteLine("[!] An operation id was not found in the response received");
                        }
                    }
                    return operationId;
                }
            }

            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    var response = ex.Response as HttpWebResponse;
                    string fail;
                    switch (response.StatusCode)
                    {
                        case HttpStatusCode.BadRequest:
                            //Handle 400 Error
                            fail = $"[!] Received a 400 response from the API. Please make sure your query has the correct syntax. Example --query \"OS | where (OSArchitecture == '64-bit')\"";
                            break;
                        case HttpStatusCode.NotFound:
                            // Handle HTTP 404 error
                            fail = $"[!] No HTTP resource was found that matches the request URI. Please make sure you are using valid syntax for the collectionId or resourceId you are trying to reach ";
                            break;
                        case HttpStatusCode.InternalServerError:
                            // Handle HTTP 500 error
                            fail = $"[!] A 500 internal error server was received from the API. Make sure the AdminService API is running";
                            break;
                        default:
                            // Handle other HTTP errors
                            fail = $"An error message was received from the API. Please try again";
                            break;
                    }

                    Console.WriteLine(fail);
                    return "";
                }

                else if (ex.Status == WebExceptionStatus.NameResolutionFailure)
                {
                    // Handle DNS resolution failure error
                    Console.WriteLine($"[!] The remote name could not be resolved. Please check the name of the Managing Point or that you can reach it");
                    return "";
                }

                return "";
            }
        }

            //This functions will periodically check the response status we get when check that an operation has completed
            //By default it will make 5 attempts before exiting this value might need to be modified when working on larger environments
            public static async Task<string> CheckOperationStatusAsync(string managementPoint, string query, string collectionName, string deviceId, string[] timeoutValues, bool json)

            {
                var opId = TriggerAdminServiceQuery(managementPoint, query, collectionName, deviceId);
                string url = null;

                if (opId == "")
                {
                    return opId;
                }

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


                //Here we try to stop the function that retrieves results from Rest API to loop infinitely by placing a cap after 5 attempts. Value can be modified with the --delay-timeout flag
                while (status != 200 && counter < int.Parse(timeoutValues[1]))
                {
                    response = await client.GetAsync(url);
                    status = (int)response.StatusCode;

                    if (status != 200)
                    {
                        counter++;
                        Console.WriteLine($"[+] Attempt {counter}: Checking for query operation to complete");
                        await Task.Delay(TimeSpan.FromSeconds(int.Parse(timeoutValues[0])));
                    }
                }

                if (status == 200)
                {
                    //Success message after retrieving operation results data
                    Console.WriteLine("[+] Successfully retrieved results from AdminService");

                    //Here we start deserializing the received JSON
                    var reqBody = await response.Content.ReadAsStringAsync();
                    var jsonBody = reqBody.Replace("\\r\\n\\r\\n", Environment.NewLine);
                    var jsonObject = JsonConvert.DeserializeObject<JToken>(jsonBody);

                    if (json)
                    {
                        // Here we display the output as JSON after the user supplies the required flag
                        Console.WriteLine($"\r\n\r\n----------------  CMPivot data  ------------------\r\n");
                        return jsonObject.ToString();
                    }

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
                    string header;

                    // Here we start parsing the JSON to display it in a command line and make it as readable as possible
                    foreach (var item in result1)
                    {
                        header = $"\r\n\r\n---------------- CMPivot data #{counter2} ------------------";
                        output.AppendLine(string.Format(header));
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
                        } output.AppendLine("--------------------------------------------");
                    }
                    return output.ToString();
                }
                else
                {   
                    string fail = "";
                    if (status == 404)
                        {
                        //Note we also get a 404 while results are not ready so when this message is for when 404 is received after we got an operationId and the timeout limit was reached
                            fail = $"[!] Received a 404 response after the set timeout was reached. It might mean that the device is not online or timeout value is too short. You can also try to retrieve results manually using the retrieved OpeartionId {opId}";
                        }
                        return fail.ToString();
                    }
            }

            // Entry point with arguments provided by user or defaults from command handler
            public static async Task Main(string managementPoint, string query, string collectionName, string deviceId, string[] timeoutValues, bool json)
            {
                var CMPdata = await CheckOperationStatusAsync(managementPoint, query, collectionName, deviceId, timeoutValues, json);
                Console.WriteLine("\r\n\r\n" + CMPdata + "\r\n\r\n");
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
