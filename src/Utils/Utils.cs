using System.IO;
using System.Text;
using System;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;

namespace HMNT.SimpDNS
{
    // Network byte order is standardized to be big endian 
    public class Utils
    {

        #region Creation

        public static byte[] CreateQueryPacket(DnsQuestionRecord question, ushort transactionId = 0)
        {
            // If no transaction ID is provided, generate a random one
            if (transactionId == 0)
            {
                Random random = new Random();
                transactionId = (ushort)random.Next(0, 65535);
            }

            DnsPacket packet = new DnsPacket();
            packet.Header.TransactionID = transactionId;
            packet.Header.Flags = Dns.FlagRD;  // Set recursion desired flag
            packet.Header.QuestionCount = 1;
            packet.Header.AnswerRecordCount = 0;
            packet.Header.AuthorityCount = 0;
            packet.Header.AdditionalRecordCount = 0;

            packet.Questions.Add(question);
            
            return DnsPacket.SerializeToBytes(packet);
        }

        public static DnsResourceRecord CreateFromLocalResolution(string localResolution, ushort questionType, string questionDomain)
        {
            byte[] rdata;
            
            switch (questionType)
            {
                case Dns.TypeA:
                    // A record: 4 bytes of IPv4 address
                    var ipv4 = IPAddress.Parse(localResolution);
                    rdata = ipv4.GetAddressBytes();
                    break;
                    
                case Dns.TypeAAAA:
                    // AAAA record: 16 bytes of IPv6 address
                    var ipv6 = IPAddress.Parse(localResolution);
                    rdata = ipv6.GetAddressBytes();
                    break;
                    
                case Dns.TypeNS:
                case Dns.TypeCNAME:
                    // These types contain a domain name - encode it properly
                    using (var ms = new MemoryStream())
                    using (var writer = new BinaryWriter(ms))
                    {
                        DnsPacket.WriteDomainName(writer, localResolution);
                        rdata = ms.ToArray();
                    }
                    break;                    
                default:
                    throw new NotSupportedException($"DNS record type {questionType} not supported for local resolution");
            }
            
            return new DnsResourceRecord
            {
                RName = questionDomain,
                RType = questionType,
                RClass = Dns.ClassINET,
                TTL = 3600,
                RDLength = (ushort)rdata.Length,
                RData = rdata
            };
        }
        
        #endregion


        #region Byte Order Conversions

        public static ushort NetworkToHostOrder(ushort value)
        {
            if (BitConverter.IsLittleEndian)
            {
                return (ushort)((value >> 8) | (value << 8));
            }
            return value;
        }
        
        public static ushort HostToNetworkOrder(ushort value)
        {
            if (BitConverter.IsLittleEndian)
            {
                return (ushort)((value >> 8) | (value << 8));
            }
            return value;
        }
        
        public static uint NetworkToHostOrder(uint value)
        {
            if (BitConverter.IsLittleEndian)
            {
                return ((value >> 24) & 0xFF) |
                       ((value >> 8) & 0xFF00) |
                       ((value << 8) & 0xFF0000) |
                       ((value << 24) & 0xFF000000);
            }
            return value;
        }
        
        public static uint HostToNetworkOrder(uint value)
        {
            if (BitConverter.IsLittleEndian)
            {
                return ((value >> 24) & 0xFF) |
                       ((value >> 8) & 0xFF00) |
                       ((value << 8) & 0xFF0000) |
                       ((value << 24) & 0xFF000000);
            }
            return value;
        }

        #endregion
        

        #region Domain Name Extraction

        public static List<string> ExtractNameservers(List<DnsResourceRecord> authorityRecords, byte[] fullPacket)
        {
            List<string> nameservers = new List<string>();
            
            foreach (var record in authorityRecords)
            {
                if (record.RType == Dns.TypeNS)
                {
                    try {
                        string nameserver = Utils.ExtractDomainNameFromRData(record.RData, fullPacket);
                        if (!string.IsNullOrEmpty(nameserver))
                        {
                            nameservers.Add(nameserver);
                            Cli.Log($"Successfully extracted nameserver: {nameserver}");
                        }
                    }
                    catch (Exception e) {
                        Cli.LogError($"Error extracting nameserver: {e.Message}");
                    }
                }
            }
            
            return nameservers;
        }

        public static string ReadDomainName(BinaryReader reader, byte[] fullPacket, int maxDepth = 10)
        {
            if (maxDepth <= 0)
            {
                throw new InvalidOperationException("Maximum DNS name compression depth exceeded");
            }

            StringBuilder domainName = new StringBuilder();
            byte labelLength = reader.ReadByte();
            
            while (labelLength > 0)
            {
                // Check if this is a pointer (compression)
                if ((labelLength & 0xC0) == 0xC0)  // Checks for 11xxxxxx in the first byte
                {
                    int offset = ((labelLength & 0x3F) << 8) | reader.ReadByte();
                    
                    if (offset >= fullPacket.Length)
                    {
                        throw new InvalidOperationException($"Invalid compression pointer offset {offset} (packet length: {fullPacket.Length})");
                    }
                    
                    long currentPosition = reader.BaseStream.Position;
                    
                    using (var ms = new MemoryStream(fullPacket))
                    using (var newReader = new BinaryReader(ms))
                    {
                        ms.Position = offset;
                        if (domainName.Length > 0)
                            domainName.Append(".");
                        domainName.Append(ReadDomainName(newReader, fullPacket, maxDepth - 1));
                    }
                    
                    reader.BaseStream.Position = currentPosition;
                    return domainName.ToString();
                }
                
                // Regular label
                if (labelLength > 63)
                {
                    throw new InvalidOperationException($"Invalid label length: {labelLength}");
                }
                
                byte[] labelBytes = reader.ReadBytes(labelLength);
                string label = Encoding.ASCII.GetString(labelBytes);
                
                if (domainName.Length > 0)
                    domainName.Append(".");
                domainName.Append(label);
                
                labelLength = reader.ReadByte();
            }
            
            return domainName.ToString();
        }

        public static string ExtractDomainNameFromRData(byte[] rdata, byte[] fullPacket = null)
        {
            try {
                using (var ms = new MemoryStream(rdata))
                using (var reader = new BinaryReader(ms))
                {
                    // If we have the full packet, use it for compression resolution
                    // Otherwise, just use the RDATA itself (which works for uncompressed names)
                    byte[] packetToUse = fullPacket ?? rdata;
                    
                    return ReadDomainName(reader, packetToUse);
                }
            }
            catch (Exception e) {
                Cli.LogError($"Error extracting domain name from RDATA: {e.Message}");
                return null;
            }
        }

        #endregion
    }    
}