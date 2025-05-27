using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;

// <summary>
// [1] http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
// </summary>

namespace HMNT.SimpDNS
{
    public class DnsPacket
    {
        public DnsHeader Header { get; set; } = new DnsHeader();
        public List<DnsQuestionRecord> Questions { get; set; }
        public List<DnsResourceRecord> Answers { get; set; }
        public List<DnsResourceRecord> Authority { get; set; }
        public List<DnsResourceRecord> Additional { get; set; }
        public byte[] FullPacketBytes { get; set; } = Array.Empty<byte>();

        public DnsPacket()
        {
            Questions = new List<DnsQuestionRecord>();
            Answers = new List<DnsResourceRecord>();
            Authority = new List<DnsResourceRecord>();
            Additional = new List<DnsResourceRecord>();
        }

        public static DnsPacket DeserializeFrom(byte[] bytes)
        {
            DnsPacket packet = ParseDnsPacket(bytes);
            packet.FullPacketBytes = bytes; // Store the full packet bytes
            return packet;
        }


        public static byte[] SerializeToBytes(DnsPacket packet, bool allowTruncateForUdp = true)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(ms))
                {
                    // Convert all header fields to network byte order
                    writer.Write(Utils.HostToNetworkOrder(packet.Header.TransactionID));

                    long flagsStartingPoint = ms.Position; // In case we want to truncate
                    writer.Write(Utils.HostToNetworkOrder(packet.Header.Flags));

                    writer.Write(Utils.HostToNetworkOrder(packet.Header.QuestionCount));
                    writer.Write(Utils.HostToNetworkOrder(packet.Header.AnswerRecordCount));
                    writer.Write(Utils.HostToNetworkOrder(packet.Header.AuthorityCount));
                    writer.Write(Utils.HostToNetworkOrder(packet.Header.AdditionalRecordCount));

                    foreach (var question in packet.Questions)
                    {
                        WriteDomainName(writer, question.QName);
                        writer.Write(Utils.HostToNetworkOrder(question.QType));
                        writer.Write(Utils.HostToNetworkOrder(question.QClass));
                    }

                    foreach (var recordType in new List<List<DnsResourceRecord>> { packet.Answers, packet.Authority, packet.Additional })
                    {
                        foreach (var record in recordType)
                        {
                            WriteDomainName(writer, record.RName);
                            writer.Write(Utils.HostToNetworkOrder(record.RType));
                            writer.Write(Utils.HostToNetworkOrder(record.RClass));
                            writer.Write(Utils.HostToNetworkOrder(record.TTL));
                            
                            // Calculate the correct RDLength based on the actual RData
                            byte[] rdataToWrite = GetCorrectRData(record.RType, record.RData);
                            writer.Write(Utils.HostToNetworkOrder((ushort)rdataToWrite.Length));
                            writer.Write(rdataToWrite);
                        }
                    }
                    
                    // Check if the packet is too large for UDP
                    // Then modify the truncation flag
                    if (allowTruncateForUdp && ms.Length > Dns.MaxUDPMessageSize)
                    {
                        long currentPosition = ms.Position;

                        ms.Position = flagsStartingPoint;
                        writer.Write(Utils.HostToNetworkOrder( (ushort) (packet.Header.Flags | (ushort) Dns.FlagTC)));

                        ms.SetLength(Dns.MaxUDPMessageSize);

                        // Not resetting it makes it do weird things idk why
                        ms.Position = currentPosition > Dns.MaxUDPMessageSize ? Dns.MaxUDPMessageSize : currentPosition;
                    }

                    writer.Flush();
                }
                
                return ms.ToArray();
            }
        }

        private static byte[] GetCorrectRData(ushort RType, byte[] RData)
        {
            // For record types that contain domain names, we need to ensure
            // the domain names are encoded without compression PTRs
            switch (RType)
            {
                case Dns.TypeNS:
                case Dns.TypeCNAME:
                case Dns.TypePTR:
                    // These types contain a single domain name in RDATA
                    using (var ms = new MemoryStream())
                    using (var writer = new BinaryWriter(ms))
                    {
                        string domainName = Utils.ExtractDomainNameFromRData(RData);
                        WriteDomainName(writer, domainName);
                        return ms.ToArray();
                    }

                case Dns.TypeMX:
                    // MX records have a 16-bit preference value followed by a domain name
                    using (var ms = new MemoryStream())
                    using (var writer = new BinaryWriter(ms))
                    {
                        // Use the Utils method and parse preference separately
                        var (preference, domainName) = ParseMXFromRData(RData);
                        writer.Write(Utils.HostToNetworkOrder(preference));
                        WriteDomainName(writer, domainName);
                        return ms.ToArray();
                    }

                case Dns.TypeSOA:
                    // SOA records are more complex - for now, return the stored RData
                    // You may need to implement proper SOA handling later
                    return RData;

                default:
                    // For A, AAAA, and other simple record types, return as-is
                    return RData;
            }
        }

        private static (ushort preference, string domainName) ParseMXFromRData(byte[] rdata)
        {
            using (var ms = new MemoryStream(rdata))
            using (var reader = new BinaryReader(ms))
            {
                ushort preference = Utils.NetworkToHostOrder(reader.ReadUInt16());
                
                var labels = new List<string>();
                while (ms.Position < ms.Length)
                {
                    byte length = reader.ReadByte();
                    if (length == 0) break;
                    
                    if (length > 63)
                    {
                        throw new InvalidOperationException("Compression pointers not supported in this context");
                    }
                    
                    byte[] labelBytes = reader.ReadBytes(length);
                    labels.Add(Encoding.ASCII.GetString(labelBytes));
                }
                
                return (preference, string.Join(".", labels));
            }
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            
            sb.AppendLine(Header.ToString());
            
            // Questions section
            sb.AppendLine(";QUESTION");
            foreach (var q in Questions)
            {
                sb.AppendLine(q.ToString());
            }
            
            // Answer section
            sb.AppendLine(";ANSWER");
            foreach (var a in Answers)
            {
                sb.AppendLine(a.ToString());
            }
            
            // Authority section
            sb.AppendLine(";AUTHORITY");
            foreach (var a in Authority)
            {
                sb.AppendLine(a.ToString());
            }
            
            // Additional section
            sb.AppendLine(";ADDITIONAL");
            foreach (var a in Additional)
            {
                sb.AppendLine(a.ToString());
            }
            
            return sb.ToString();
        }

        #region Parsing

        public static DnsPacket ParseDnsPacket(byte[] responseBytes)
        {
            DnsPacket response = new DnsPacket();
            
            using (var ms = new MemoryStream(responseBytes))
            using (var reader = new BinaryReader(ms))
            {
                // Parse header
                response.Header.TransactionID = Utils.NetworkToHostOrder(reader.ReadUInt16());
                response.Header.Flags = Utils.NetworkToHostOrder(reader.ReadUInt16());
                response.Header.QuestionCount = Utils.NetworkToHostOrder(reader.ReadUInt16());
                response.Header.AnswerRecordCount = Utils.NetworkToHostOrder(reader.ReadUInt16());
                response.Header.AuthorityCount = Utils.NetworkToHostOrder(reader.ReadUInt16());
                response.Header.AdditionalRecordCount = Utils.NetworkToHostOrder(reader.ReadUInt16());
                
                // Parse questions
                for (int i = 0; i < response.Header.QuestionCount; i++)
                {
                    DnsQuestionRecord question = new DnsQuestionRecord();
                    question.QName = Utils.ReadDomainName(reader, responseBytes);
                    question.QType = Utils.NetworkToHostOrder(reader.ReadUInt16());
                    question.QClass = Utils.NetworkToHostOrder(reader.ReadUInt16());
                    response.Questions.Add(question);
                }
                
                // Parse answers
                for (int i = 0; i < response.Header.AnswerRecordCount; i++)
                {
                    response.Answers.Add(ParseResourceRecord(reader, responseBytes));
                }
                
                // Parse authority
                for (int i = 0; i < response.Header.AuthorityCount; i++)
                {
                    response.Authority.Add(ParseResourceRecord(reader, responseBytes));
                }
                
                // Parse additional
                for (int i = 0; i < response.Header.AdditionalRecordCount; i++)
                {
                    response.Additional.Add(ParseResourceRecord(reader, responseBytes));
                }
            }
            
            return response;
        }

        public static DnsHeader ParseHeader(BinaryReader reader)
        {
            DnsHeader header = new DnsHeader
            {
                TransactionID = Utils.NetworkToHostOrder(reader.ReadUInt16()),
                Flags = Utils.NetworkToHostOrder(reader.ReadUInt16()),
                QuestionCount = Utils.NetworkToHostOrder(reader.ReadUInt16()),
                AnswerRecordCount = Utils.NetworkToHostOrder(reader.ReadUInt16()),
                AuthorityCount = Utils.NetworkToHostOrder(reader.ReadUInt16()),
                AdditionalRecordCount = Utils.NetworkToHostOrder(reader.ReadUInt16())
            };
            
            return header;
        }

        public static List<DnsQuestionRecord> ParseQuestions(BinaryReader reader, byte[] fullPacket, ushort count)
        {
            List<DnsQuestionRecord> questions = new List<DnsQuestionRecord>();
            for (int i = 0; i < count; i++)
            {
                questions.Add(ParseQuestion(reader, fullPacket));
            }

            return questions;
        }

        public static DnsQuestionRecord ParseQuestion(BinaryReader reader, byte[] fullPacket)
        {
            DnsQuestionRecord question = new DnsQuestionRecord();
            
            question.QName = Utils.ReadDomainName(reader, fullPacket);
            question.QType = Utils.NetworkToHostOrder(reader.ReadUInt16());
            question.QClass = Utils.NetworkToHostOrder(reader.ReadUInt16());
            
            return question;
        }

        public static List<DnsResourceRecord> ParseResourceRecords(BinaryReader reader, byte[] fullPacket, ushort count)
        {
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();
            for (int i = 0; i < count; i++)
            {
                records.Add(ParseResourceRecord(reader, fullPacket));
            }

            return records;
        }
        
        public static DnsResourceRecord ParseResourceRecord(BinaryReader reader, byte[] fullPacket)
        {
            DnsResourceRecord record = new DnsResourceRecord();
            
            // Parse NAME field using the domain name reading utility that handles compression
            record.RName = Utils.ReadDomainName(reader, fullPacket);
            
            // Parse TYPE and CLASS fields (2 octets each)
            record.RType = Utils.NetworkToHostOrder(reader.ReadUInt16());
            record.RClass = Utils.NetworkToHostOrder(reader.ReadUInt16());
            
            // Parse TTL field (4 octets)
            record.TTL = Utils.NetworkToHostOrder(reader.ReadUInt32());
            
            // Parse RDLENGTH field (2 octets)
            record.RDLength = Utils.NetworkToHostOrder(reader.ReadUInt16());
            
            // Store the current position to handle RDATA parsing
            long startPosition = reader.BaseStream.Position;
            
            // Read raw RDATA first
            record.RData = reader.ReadBytes(record.RDLength);
            
            // For certain record types, we need to handle domain name compression within RDATA
            switch (record.RType)
            {
                case Dns.TypeNS:
                case Dns.TypeCNAME:
                case Dns.TypePTR:
                    // These types contain a single domain name in RDATA
                    // Reset position to start of RDATA to properly handle compression
                    reader.BaseStream.Position = startPosition;
                    using (var ms = new MemoryStream())  // Create expandable MemoryStream
                    using (var writer = new BinaryWriter(ms))
                    {
                        string domainName = Utils.ReadDomainName(reader, fullPacket);
                        WriteDomainName(writer, domainName);
                        record.RData = ms.ToArray();  // Get the final byte array
                    }
                    break;

                case Dns.TypeMX:
                    // MX records have a 16-bit preference value followed by a domain name
                    reader.BaseStream.Position = startPosition;
                    using (var ms = new MemoryStream())  // Create expandable MemoryStream
                    using (var writer = new BinaryWriter(ms))
                    {
                        ushort preference = Utils.NetworkToHostOrder(reader.ReadUInt16());
                        string domainName = Utils.ReadDomainName(reader, fullPacket);
                        
                        writer.Write(Utils.HostToNetworkOrder(preference));
                        WriteDomainName(writer, domainName);
                        record.RData = ms.ToArray();  // Get the final byte array
                    }
                    break;

                case Dns.TypeSOA:
                    // SOA records have complex structure with multiple fields
                    reader.BaseStream.Position = startPosition;
                    using (var ms = new MemoryStream())  // Create expandable MemoryStream
                    using (var writer = new BinaryWriter(ms))
                    {
                        string mname = Utils.ReadDomainName(reader, fullPacket);
                        string rname = Utils.ReadDomainName(reader, fullPacket);
                        uint serial = Utils.NetworkToHostOrder(reader.ReadUInt32());
                        uint refresh = Utils.NetworkToHostOrder(reader.ReadUInt32());
                        uint retry = Utils.NetworkToHostOrder(reader.ReadUInt32());
                        uint expire = Utils.NetworkToHostOrder(reader.ReadUInt32());
                        uint minimum = Utils.NetworkToHostOrder(reader.ReadUInt32());

                        WriteDomainName(writer, mname);
                        WriteDomainName(writer, rname);
                        writer.Write(Utils.HostToNetworkOrder(serial));
                        writer.Write(Utils.HostToNetworkOrder(refresh));
                        writer.Write(Utils.HostToNetworkOrder(retry));
                        writer.Write(Utils.HostToNetworkOrder(expire));
                        writer.Write(Utils.HostToNetworkOrder(minimum));
                        record.RData = ms.ToArray();  // Get the final byte array
                    }
                    break;

                case Dns.TypeA:
                    // A records are already properly handled (4 bytes of IPv4 address)
                    if (record.RDLength != 4)
                    {
                        throw new InvalidOperationException($"Invalid RDLENGTH for A record: {record.RDLength}");
                    }
                    break;

                case Dns.TypeAAAA:
                    // AAAA records are already properly handled (16 bytes of IPv6 address)
                    if (record.RDLength != 16)
                    {
                        throw new InvalidOperationException($"Invalid RDLENGTH for AAAA record: {record.RDLength}");
                    }
                    break;

                // For other record types, we've already read the raw RDATA bytes
            }
            
            // Ensure we've moved past the RDATA section
            reader.BaseStream.Position = startPosition + record.RDLength;
            
            return record;
        }

        #endregion
        
        #region Constructing
        private static Dictionary<string, int> _compressionOffsets = new Dictionary<string, int>();

        public static void WriteDomainName(BinaryWriter writer, string domain)
        {
            // Ensure the domain doesn't end with a dot for processing
            if (domain.EndsWith("."))
                domain = domain.Substring(0, domain.Length - 1);

            string remainingDomain = domain;
            while (!string.IsNullOrEmpty(remainingDomain))
            {
                // Write the next label
                int dotIndex = remainingDomain.IndexOf('.');
                string label = dotIndex == -1 ? remainingDomain : remainingDomain.Substring(0, dotIndex);
                
                // Write label length and data
                byte[] labelBytes = Encoding.ASCII.GetBytes(label);
                writer.Write((byte)labelBytes.Length);
                writer.Write(labelBytes);

                // Move to next label
                remainingDomain = dotIndex == -1 ? "" : remainingDomain.Substring(dotIndex + 1);
            }

            // Write terminating zero
            writer.Write((byte)0);
        }

        #endregion
    }
}