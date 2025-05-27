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
    public class Dns
    {
        public static ushort MaxUDPMessageSize = 512;
        public static ushort MaxTXTLength = 255;

        // DNS Record Types
        public const ushort TypeA = 1;
        public const ushort TypeNS = 2;
        public const ushort TypeCNAME = 5;
        public const ushort TypeSOA = 6;
        public const ushort TypePTR = 12; 
        public const ushort TypeMX = 15; 
        public const ushort TypeTXT = 16;
        public const ushort TypeAAAA = 28;

        // DNS Classes
        public const ushort ClassINET = 1; // the Internet (IN)
        
        // DNS Flags
        public const ushort FlagQR = 1 << 15;    // Query/Response flag
        public const ushort FlagAA = 1 << 10;    // Authoritative Answer
        public const ushort FlagTC = 1 << 9;     // Truncation
        public const ushort FlagRD = 1 << 8;     // Recursion Desired
        public const ushort FlagRA = 1 << 7;     // Recursion Available

        // SupportedDNS OpCodes
        public static ushort OpCodeQuery = 0;
        public static ushort OpCodeStatus = 2;
        
        // Response codes
        public static ushort RCodeNoError = 0;
        public static ushort RCodeFormatError = 1;
        public static ushort RCodeServerFailure = 2;
        public static ushort RCodeNXDomain = 3;
        public static ushort RCodeNotImplemented = 4;
        public static ushort RCodeRefused = 5;
        
        // Starter flags when constructing a response header
        public static ushort BasicResponseFlags = FlagQR; // only the QR flag is set
        
        // Root nameservers
        // Might as well be a waste of memory tbh.
        public static readonly List<string> RootNameservers = new List<string>
        {
            "a.root-servers.net.",
            "b.root-servers.net.",
            "c.root-servers.net.",
            "d.root-servers.net.",
            "e.root-servers.net.",
            "f.root-servers.net.",
            "g.root-servers.net.",
            "h.root-servers.net.",
            "i.root-servers.net.",
            "j.root-servers.net.",
            "k.root-servers.net.",
            "l.root-servers.net.",
            "m.root-servers.net."
        };

        // Helper functions 
        public static string GetTypeString(ushort type)
        {
            switch (type)
            {
                case 1: return "A";
                case 2: return "NS";
                case 5: return "CNAME";
                case 6: return "SOA";
                case 12: return "PTR";
                case 15: return "MX";
                case 16: return "TXT";
                case 28: return "AAAA";
                default: return $"TYPE{type}";
            }
        }

        // Will never be other than IN
        public static string GetClassString(ushort classValue)
        {
            switch (classValue)
            {
                case 1: return "IN";
                case 2: return "CS";
                case 3: return "CH";
                case 4: return "HS";
                default: return $"CLASS{classValue}";
            }
        }
    }
}