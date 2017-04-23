using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace UdpClientProgram
{
    class Program
    {
       /*
           FOR TESTING THE SERVER
       */

        public const string password = "pass";
        static void Main(string[] args)
        {
            while (true)
            {
                UdpClient client = new UdpClient();
                IPEndPoint ipep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 600);
                client.Connect(ipep);

                Console.WriteLine("Write message:");
                byte[] packet = Encoding.ASCII.GetBytes(Console.ReadLine());
                client.Send(packet, packet.Length);
                var data = client.Receive(ref ipep);


                if (data[0] == 0x02)
                {
                    data = data.Skip(1).ToArray();

                    string token = Encoding.ASCII.GetString(data);
                    string response = ComputeHash(token + password);

                    Console.WriteLine("Received authentication token: " + token);
                    Console.WriteLine("Computed password hash: " + response);

                    byte[] resp = Encoding.ASCII.GetBytes(response);
                    client.Send(resp, resp.Length);

                    data = client.Receive(ref ipep);

                    if (data[0] == 0x00)
                    {
                        Console.WriteLine("Authentication Failed");
                    }

                    if (data[0] == 0x01)
                    {
                        Console.WriteLine("Authentication Succeeded");
                    }

                }

                if (data[0] == 0xFF)
                {
                    data = data.Skip(1).ToArray();
                    Console.WriteLine("\r\n" + Encoding.ASCII.GetString(data) + "\r\n");
                }
            }
        }


        public static String ComputeHash(String value)
        {
            using (SHA256 hash = SHA256Managed.Create())
            {
                return String.Join("", hash.ComputeHash(Encoding.UTF8.GetBytes(value)).Select(item => item.ToString("x2")));
            }
        } 


    }
}
