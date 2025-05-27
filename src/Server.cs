using System;
using System.Net;
using System.Net.Sockets;

/***
https://datatracker.ietf.org/doc/html/rfc1035#autoid-36 
***/

namespace HMNT.SimpDNS
{
    public class Server
    {
        private static Config config;
        private static Cache cache;
        private static DnsHandler dnsHandler;
        
        private static int PORT = 7000;

        public static void Main()
        {                      
            StartAsync();
        }

        public static void StartAsync()
        {
            Console.WriteLine("\nStarting SimpDNS...");

            // Starting services
            config = new();
            cache = new();
            dnsHandler = new();

            PORT = config.Port;

            Thread udpThread = new Thread(UdpLoop);
            Thread tcpThread = new Thread(TcpLoop);

            udpThread.IsBackground = true;
            if (config.AllowTCP)
                tcpThread.IsBackground = true;

            udpThread.Start();
            if (config.AllowTCP)
                tcpThread.Start();

            Console.WriteLine($"Running SimpDNS; Listening on :{PORT}");

            udpThread.Join();
            if (config.AllowTCP)
                tcpThread.Join();
        }

        public static void UdpLoop()
        {
            UdpClient udpClient = new UdpClient(PORT);
            IPEndPoint ipEndpoint = null;

            while (true)
            {
                try
                {
                    byte[] requestBytes = udpClient.Receive(ref ipEndpoint);
                    byte[] responseBytes = dnsHandler.Handle(requestBytes, ipEndpoint);
                    udpClient.Send(responseBytes, responseBytes.Length, ipEndpoint);
                }
                catch (Exception e)
                {
                    Cli.LogError("Err handling DNS request (UDP): " + e.Message);
                }
            }
        }

        public static void TcpLoop()
        {
            TcpListener tcpListener = new TcpListener(IPAddress.Any, PORT);
            tcpListener.Start();

            while (true)
            {
                try
                {
                    var tcpClient = tcpListener.AcceptTcpClient();   // Blocking accept
                    var stream = tcpClient.GetStream();

                    // Read 2-byte length prefix
                    var lenBuf = new byte[2];
                    stream.Read(lenBuf, 0, 2);
                    int length = (lenBuf[0] << 8) | lenBuf[1];

                    // Read the DNS query
                    var req = new byte[length];
                    int read = 0;
                    while (read < length)
                        read += stream.Read(req, read, length - read);

                    // Process and reply
                    var remoteEP = (IPEndPoint)tcpClient.Client.RemoteEndPoint;
                    var resp = dnsHandler.Handle(req, remoteEP);

                    // Write length + data
                    var respLen = new byte[] { (byte)(resp.Length >> 8), (byte)(resp.Length & 0xFF) };
                    stream.Write(respLen, 0, 2);
                    stream.Write(resp, 0, resp.Length);
                }
                catch (Exception e)
                {
                    Cli.LogError($"Err handling DNS request (TCP): {e.Message}");
                }
            }
        }
    }
}
