using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HMNT.SimpDNS
{
    public class InternalDnsClient
    {
        public static (DnsPacket, Exception) QueryNameserver(IPAddress nameserverIP, DnsQuestionRecord question, int timeout = 2000)
        {
            try
            {
                Cli.Log($"Querying nameserver {nameserverIP} for {question.QName}", 3);

                byte[] queryPacket = Utils.CreateQueryPacket(question);
                
                using (var udpClient = new UdpClient())
                {
                    udpClient.Client.ReceiveTimeout = timeout;


                    udpClient.Connect(nameserverIP, 53);
                    udpClient.Send(queryPacket, queryPacket.Length);
                    
                    // Receive response
                    var remoteEP = new IPEndPoint(IPAddress.Any, 0);
                    byte[] responseBytes = udpClient.Receive(ref remoteEP);
                    Cli.Log("\tResponse received from " + nameserverIP + " (" + responseBytes.Length + " bytes)", 2);
                    DnsPacket responsePacket = DnsPacket.DeserializeFrom(responseBytes);
                    
                    if (responsePacket.Header.IsTruncated())
                    {
                        Cli.Log("\tResponse is truncated. Retrying with TCP...", 2);
                        return QueryNameserverTCP(nameserverIP, question, timeout);
                    }
                    
                    return (responsePacket, null);
                }
            }
            catch (Exception e)
            {
                Cli.LogError($"\tUDP query failed: {e.Message}", 2);

                // Try TCP as fallback
                try {
                    return QueryNameserverTCP(nameserverIP, question, timeout);
                }
                catch (Exception tcpEx) {
                    return (null, new Exception($"\tComplete query failed: {tcpEx.Message}"));
                }
            }
        }

        private static (DnsPacket, Exception) QueryNameserverTCP(IPAddress nameserverIP, DnsQuestionRecord question, int timeout = 2000)
        {
            try
            {
                byte[] queryPacket = Utils.CreateQueryPacket(question);
                
                using (var tcpClient = new TcpClient())
                {
                    // Try to connect to the nameserver
                    var connectTask = tcpClient.ConnectAsync(nameserverIP, 53);
                    if (!connectTask.Wait(timeout))
                    {
                        throw new TimeoutException("TCP connection timeout");
                    }
                                        
                    tcpClient.ReceiveTimeout = timeout;
                    
                    using (var stream = tcpClient.GetStream())
                    {
                        // In TCP, DNS messages are prefixed with a 2-byte length field
                        ushort queryLength = (ushort) queryPacket.Length;
                        byte[] lengthPrefix = BitConverter.GetBytes(Utils.HostToNetworkOrder(queryLength));
                                        
                        stream.Write(lengthPrefix, 0, 2);
                        stream.Write(queryPacket, 0, queryPacket.Length);
                        Cli.Log("\tTCP query sent to " + nameserverIP, 2);
                        


                        // Read the response 
                        byte[] responseLengthBytes = new byte[2];
                        int bytesRead = stream.Read(responseLengthBytes, 0, 2);
                        if (bytesRead != 2)
                        {
                            throw new Exception("Failed to read response length");
                        }
                        
                        ushort responseLengthNetwork = BitConverter.ToUInt16(responseLengthBytes, 0);
                        ushort responseLength = Utils.NetworkToHostOrder(responseLengthNetwork);
                        
                        // Read the response
                        byte[] responseBytes = new byte[responseLength];
                        int totalBytesRead = 0;
                        
                        while (totalBytesRead < responseLength)
                        {
                            int bytesRemaining = responseLength - totalBytesRead;
                            int currentBytesRead = stream.Read(responseBytes, totalBytesRead, bytesRemaining);
                            
                            if (currentBytesRead == 0)
                            {
                                throw new Exception("Connection closed before full response was received");
                            }
                            
                            totalBytesRead += currentBytesRead;
                        }
                        
                        Cli.Log("\tTCP response received from " + nameserverIP + " (" + responseBytes.Length + " bytes)", 2);
                        
                        DnsPacket responsePacket = DnsPacket.DeserializeFrom(responseBytes);
                        return (responsePacket, null);
                    }
                }
            }
            catch (Exception e)
            {
                return (null, new Exception($"TCP query failed: {e.Message}"));
            }
        }
    }
}
