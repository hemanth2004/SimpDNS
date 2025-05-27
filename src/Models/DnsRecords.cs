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
    public class DnsQuestionRecord
    {
        /* RFC1035 
        *  > Domain names in messages are expressed in terms of a sequence
        *  > of labels. Each label is represented as a one octet length field followed
        *  > by that number of octets.  Since every domain name ends with the null label
        *  > of the root, a domain name is terminated by a length byte of zero.
        */
        public string QName { get; set; } = string.Empty;

        // Types from 251 to 255
        public ushort QType;

        // Useless tbh. but 1 is expected.
        public ushort QClass;

        public override string ToString()
        {
            return $"{QName}. {Dns.GetClassString(QClass)} {Dns.GetTypeString(QType)}";
        }
    }

    public class DnsResourceRecord
    {
        // Same as above
        public string RName { get; set; } = string.Empty;
        public ushort RType;
        public ushort RClass;

        // TTL number of seconds; 0 => do not cache
        public uint TTL;

        // size of RData field in bytes
        public ushort RDLength;

        // data of the resoure record; size depends on type of RR
        // {type no./field name/size}
        // 1/Address (A)/4
        // 2/NS Domain Name (NS)/var
        // 5/CName (CNAME)/var
        // 6/Start Of Authority (SOA)/sub-fields(size) => {
        //      MName(var): domain name of master authoritative server for the zone
        //      RName(var): email of the person responsible for the zone
        //      Serial(4): version number of the RR database for the zone
        //      Refresh(4): seconds before slave requests for changes from master
        //      Retry(4): seconds before retry refresh on refresh fail
        //      Expire(4): seconds after last contact to declare slave's info as stale
        //      Minimum(4): a zone's negative cache TTL
        //  }
        // 12/PTRD Name (PTR)/var
        // 15/Mail Exchange RR (MX)/sub-fields(size) => {
        //      Preference(2): preference level
        //      Exchange(var): standard (not mail) DNS notation of the mail server ig?
        //  }
        // 16/TXT-Data (TXT)/(var)

        // Record Data
        public byte[] RData { get; set; } = Array.Empty<byte>();


        public override string ToString()
        {
            StringBuilder rdataStr = new StringBuilder();

            if (RData != null && RData.Length > 0)
            {
                if (RType == Dns.TypeA && RData.Length == 4)
                {
                    rdataStr.Append(string.Join(".", RData.Select(b => b.ToString())));
                }
                else if (RType == Dns.TypeAAAA && RData.Length == 16)
                {
                    var segments = new string[8];
                    for (int i = 0; i < 8; i++)
                    {
                        segments[i] = $"{RData[i * 2]:x2}{RData[i * 2 + 1]:x2}";
                    }
                    rdataStr.Append(string.Join(":", segments));
                }
                else if (RType == Dns.TypeNS || RType == Dns.TypeCNAME || RType == Dns.TypePTR)
                {
                    try
                    {
                        rdataStr.Append(Utils.ExtractDomainNameFromRData(RData));
                    }
                    catch
                    {
                        rdataStr.Append("<error parsing domain>");
                    }
                }
                else
                {
                    rdataStr.Append($"<{RData.Length} bytes>");
                }
            }
            
            return $"{RName}. {TTL} {Dns.GetClassString(RClass)} {Dns.GetTypeString(RType)} {rdataStr.ToString()}";
        }
    }
}