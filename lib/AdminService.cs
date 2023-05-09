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
using System.Management;

namespace SharpSCCM
{

    public static class AdminService
    {
        //This function handles the inital query to AdminService and returns the Operation Id
        public static string TriggerAdminServiceQuery(string managementPoint, string sitecode, string query, string collectionName, string deviceId)
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

            Console.WriteLine($"[+] URL: \"{url}\"");
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
                            Console.WriteLine($"[+] OperationId found: {operationId}");
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
                            //Handle 400 Error and fall back to SMS Provider method call to insure query is valid
                            query = !string.IsNullOrEmpty(query) ? Helpers.EscapeBackslashes(query) : null;
                            Console.WriteLine("[!] Received a 400 ('Bad request') response from the API. Falling back to SMS Provider method ");
                            var SMS_OperationId = InitiateClientOperationExMethodCall(query, managementPoint, sitecode, collectionName, deviceId);
                            if (SMS_OperationId != 0)
                            {
                                return SMS_OperationId.ToString();
                            }
                            fail = $"[!] The call to SMS Provider method failed. Please make sure your query has the correct syntax. Example --query \"OS | where (OSArchitecture == '64-bit')\"";
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

        //This function will periodically check the response status we get when check that an operation has completed
        //By default it will make 5 attempts before exiting this value might need to be modified when working on larger environments
        public static async Task<string> CheckOperationStatusAsync(string managementPoint, string sitecode, string query, string collectionName, string deviceId, string[] timeoutValues, bool json)

        {

            query = !string.IsNullOrEmpty(query) ? Helpers.EscapeBackslashes(query) : null;
            var opId = TriggerAdminServiceQuery(managementPoint, sitecode, query, collectionName, deviceId);
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
                    Console.WriteLine($"[+] Attempt {counter} of {timeoutValues[1]}: Checking for query operation to complete\r\n[+] URL: \"{url}\"\r\n[+] {timeoutValues[0]} seconds until next attempt");
                    await Task.Delay(TimeSpan.FromSeconds(int.Parse(timeoutValues[0])));
                }
            }

            if (status == 200)
            {

                //Success message after retrieving operation results data
                Console.WriteLine("[+] Successfully retrieved results from AdminService\r");
                //Here we start deserializing the received JSON
                var reqBody = await response.Content.ReadAsStringAsync();
                var jsonBody = reqBody.Replace("\\r\\n\\r\\n", Environment.NewLine);
                var jsonObject = JsonConvert.DeserializeObject<JToken>(jsonBody);

                if (json)
                {
                    // Here we display the output as JSON after the user supplies the required flag
                    Console.WriteLine($"\r----------------  CMPivot data  ------------------\r");
                    return jsonObject.ToString();
                }

                // The file content query returns files line by line. We use this to output lines together
                if (query.Contains("FileContent("))
                {
                    JObject obj = JObject.Parse(jsonBody);
                    JArray results = (JArray)obj["value"]["Result"];
                    if (results.Count != 0)
                    {
                        StringBuilder sb = new StringBuilder();
                        foreach (JObject result in results)
                        {
                            sb.AppendLine(result["Content"].ToString());
                        }

                        string contentString = sb.ToString();
                        Console.WriteLine("\r--------------- File Contents ---------------\r");
                        Console.WriteLine(contentString + "\r--------------------------------------------\r");
                        return null;
                    }
                    Console.WriteLine("[!] The retrieved results for the FileContent operation came back empty. Make sure the file exists or check query syntax");
                    return null;
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
                    header = $"---------------- CMPivot data #{counter2} ------------------";
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
                    }
                    output.AppendLine("\n--------------------------------------------");
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

        public static uint InitiateClientOperationExMethodCall(string query, string managementPoint, string sitecode, string CollectionName, string deviceId)
        {
            try
            {
                // Get the SMS_ClientOperation WMI class
                ManagementScope scope = MgmtUtil.NewWmiConnection(managementPoint, null, sitecode);
                ManagementClass clientOperationClass = new ManagementClass(scope, new ManagementPath("SMS_ClientOperation"), null);

                //Prepare the content of the Param Parameter for the method call
                var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(query);
                string base64 = System.Convert.ToBase64String(plainTextBytes);
                string ParametersXML = $"<ScriptParameters><ScriptParameter ParameterGroupGuid=\"\" ParameterGroupName=\"PG_\" ParameterName=\"kustoquery\" ParameterDataType=\"System.String\" ParameterVisibility=\"0\" ParameterType=\"0\" ParameterValue=\"E:RSgwKQ==\"/><ScriptParameter ParameterGroupGuid=\"\" ParameterGroupName=\"PG_\" ParameterName=\"select\" ParameterDataType=\"System.String\" ParameterVisibility=\"0\" ParameterType=\"0\" ParameterValue=\"E:RGV2aWNlOkRldmljZSxMaW5lOk51bWJlcixDb250ZW50OlN0cmluZw==\"/><ScriptParameter ParameterGroupGuid=\"\" ParameterGroupName=\"PG_\" ParameterName=\"wmiquery\" GroupClass=\"\" ParameterDataType=\"System.String\" ParameterVisibility=\"0\" ParameterType=\"0\" ParameterValue=\"E:{base64}\"/></ScriptParameters>";
                SHA256 SHA256 = new SHA256Cng();
                byte[] Bytes = SHA256.ComputeHash(Encoding.Unicode.GetBytes(ParametersXML));
                string ParametersHash = (string.Join("", Bytes.Select(b => b.ToString("X2")))).ToLower();
                string xml = "<ScriptContent ScriptGuid='7DC6B6F1-E7F6-43C1-96E0-E1D16BC25C14'>" +
                                "<ScriptVersion>1</ScriptVersion>" +
                                "<ScriptType>0</ScriptType>" +
                                "<ScriptHash ScriptHashAlg='SHA256'>e77a6861a7f6fc25753bc9d7ab49c26d2ddfc426f025b902acefc406ae3b3732</ScriptHash>" +
                                "<ScriptParameters>" +
                                    "<ScriptParameter ParameterGroupGuid='' ParameterGroupName='PG_' ParameterName='kustoquery' ParameterDataType='System.String' ParameterVisibility='0' ParameterType='0' ParameterValue='E:RSgwKQ=='/>" +
                                    "<ScriptParameter ParameterGroupGuid='' ParameterGroupName='PG_' ParameterName='select' ParameterDataType='System.String' ParameterVisibility='0' ParameterType='0' ParameterValue='E:RGV2aWNlOkRldmljZSxMaW5lOk51bWJlcixDb250ZW50OlN0cmluZw=='/>" +
                                    $"<ScriptParameter ParameterGroupGuid='' ParameterGroupName='PG_' ParameterName='wmiquery' GroupClass='' ParameterDataType='System.String' ParameterVisibility='0' ParameterType='0' ParameterValue='E:{base64}'/>" +
                                "</ScriptParameters>" +
                                $"<ParameterGroupHash ParameterHashAlg='SHA256'>{ParametersHash}</ParameterGroupHash>" +
                            "</ScriptContent>";

                string input2 = xml;
                var plainTextBytes2 = System.Text.Encoding.UTF8.GetBytes(input2);
                string base642 = System.Convert.ToBase64String(plainTextBytes2);

                // Set up the rest of the input parameters for the method call
                ManagementBaseObject inParams = clientOperationClass.GetMethodParameters("InitiateClientOperationEx");
                inParams["Type"] = (uint)145;
                inParams["TargetCollectionID"] = CollectionName;
                uint.TryParse(deviceId, out uint devId);
                inParams["TargetResourceIDs"] = new uint[] { devId };
                inParams["RandomizationWindow"] = null;
                inParams["Param"] = base642;

                // Call the InitiateClientOperationEx method with the specified arguments
                ManagementBaseObject outParams = clientOperationClass.InvokeMethod("InitiateClientOperationEx", inParams, null);
                uint returnValue = Convert.ToUInt32(outParams.Properties["OperationID"].Value);
                if (returnValue > 0)
                {
                    Console.WriteLine("[+] Fallback Method call succeeded");
                    return returnValue;
                }
                else
                {
                    Console.WriteLine("[!] Method call failed with error code {0}.", returnValue);
                    return 0;
                }
            }
            catch (ManagementException e)
            {
                Console.WriteLine("[!] An error occurred while attempting to call the SMS Provider: " + e.Message);
                return 0;
            }
        }

        // Entry point with arguments provided by user or defaults from command handler
        public static async Task Main(string managementPoint, string sitecode, string query, string collectionName, string deviceId, string[] timeoutValues, bool json)
        {
            var CMPdata = await CheckOperationStatusAsync(managementPoint, sitecode, query, collectionName, deviceId, timeoutValues, json);
            if (!string.IsNullOrWhiteSpace(CMPdata))
            {
                Console.WriteLine("\r" + CMPdata + "\r");
            }
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
