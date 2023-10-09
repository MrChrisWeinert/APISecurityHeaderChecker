using System.Diagnostics;
using System.Net;

namespace API_Security_Header_Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            Program program = new Program();

            List<string> listOfHeadersToVerifyDoesExist = new List<string>();
            List<string> listOfHeadersToVerifyDoesNotExist = new List<string>();
            
            //Positive Test. Ensure these headers exist.
            listOfHeadersToVerifyDoesExist.Add("Cache-Control");
            listOfHeadersToVerifyDoesExist.Add("Content-Security-Policy");
            listOfHeadersToVerifyDoesExist.Add("Content-Type");
            listOfHeadersToVerifyDoesExist.Add("Strict-Transport-Security");
            listOfHeadersToVerifyDoesExist.Add("X-Content-Type-Options");
            listOfHeadersToVerifyDoesExist.Add("X-Frame-Options");

            //Negative Test. Ensure these headers do not exist.
            listOfHeadersToVerifyDoesNotExist.Add("Server");
            listOfHeadersToVerifyDoesNotExist.Add("X-Powered-By");
            listOfHeadersToVerifyDoesNotExist.Add("X-AspNet-Version");
            listOfHeadersToVerifyDoesNotExist.Add("X-AspNetMvc-Version");

            if (args.Length !=2 )
            {
                Console.WriteLine("You are missing some parameters. Use '-u' to test a single URL or -f to test a list of URLs provided in a text file.");
                Console.WriteLine("Examples:");
                Console.WriteLine("API_Security_Header_Tester.exe -u https://example.com");
                Console.WriteLine(@"API_Security_Header_Tester.exe -f 'C:\Temp\UrlList.txt'");
                return;
            }
            //Single URL
            else if (args[0] == "-u")
            {
                Console.WriteLine("URL,Action,Header");
                string url = args[1];
                program.ProcessUrl(url, listOfHeadersToVerifyDoesExist, listOfHeadersToVerifyDoesNotExist);
            }
            //File containing a list of URLs
            else if (args[0] == "-f")
            {
                Console.WriteLine("URL,Action,Header,Recommended Value");
                string urlFileList = args[1];
                using (StreamReader sr = new StreamReader(urlFileList))
                {
                    string url = sr.ReadLine();
                    //Don't process URLs that are REMarked out.
                    // This lets us REM out lines to exclude them from future runs. 
                    while (url != null && !url.StartsWith("REM "))
                    {
                        program.ProcessUrl(url, listOfHeadersToVerifyDoesExist, listOfHeadersToVerifyDoesNotExist);
                        url = sr.ReadLine();
                    }
                }
            }
        }
        public void ProcessUrl(string url, List<string> listOfHeadersToVerifyDoesExist, List<string> listOfHeadersToVerifyDoesNotExist)
        {
            HttpClient httpClient = new HttpClient();
            httpClient.BaseAddress = new Uri(url);
            HttpRequestMessage httpRequestMessage = new HttpRequestMessage();
            httpRequestMessage.Method = HttpMethod.Get;
            HttpResponseMessage httpResponseMessage = httpClient.Send(httpRequestMessage);
            //Headers are stored in two (or more?) different places. The next two lines take care of the two known places.
            List<string> responseMessageContentHeaders = httpResponseMessage.Content.Headers.ToList().Select(x => x.Key).ToList();
            List<string> responseMessageHeaders = httpResponseMessage.Headers.ToList().Select(x => x.Key).ToList().ToList();
            List<string> headerKeys = new List<string>();
            headerKeys.AddRange(responseMessageContentHeaders);
            headerKeys.AddRange(responseMessageHeaders);
            List<string> keysThatShouldExist = headerKeys.Intersect(listOfHeadersToVerifyDoesExist).ToList();
            List<string> keysThatShouldntExist = headerKeys.Intersect(listOfHeadersToVerifyDoesNotExist).ToList();
            //Positive check - ensure that we have all the headers we're supposed to have.
            foreach (string key in listOfHeadersToVerifyDoesExist.Except(keysThatShouldExist))
            {
                string recommendedValue = "";
                switch (key)
                {
                    case "Cache-Control":
                        recommendedValue = "no-store";
                        break;
                    case "Content-Security-Policy":
                        recommendedValue = "frame-ancestors 'none'";
                        break;
                    case "X-Content-Type-Options":
                        recommendedValue = "nosniff";
                        break;
                    case "X-Frame-Options":
                        recommendedValue = "DENY";
                        break;
                }
                Console.WriteLine($"{url},ADD,{key},{recommendedValue}");
            }

            //Negative check - ensure that aren't using headers that we shouldn't be using.
            foreach (string key in listOfHeadersToVerifyDoesNotExist.Intersect(headerKeys))
            {
                Console.WriteLine($"{url},REMOVE,{key},");
            }
        }
    }
}