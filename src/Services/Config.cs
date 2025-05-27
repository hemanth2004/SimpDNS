using Tommy;
using System.Text;
using System.Net;
using System.IO;
using System.Net.Sockets;

// Docs: https://github.com/dezhidki/Tommy

namespace HMNT.SimpDNS
{
    public class Config
    {
        public static Config Instance = null;
        
        public static readonly string CONFIG_FILE_PATH = "config.toml";

        public int Port;
        public bool AllowTCP;
        public string DBPath;
        public string DBSetupSQL;
        public int CachedNSTTL;
        public int FallbackMinimumTTL;

        public TomlTable table;

        public Config()
        {
            // Singleton
            if (Instance == null) { Instance = this; }

            using(StreamReader reader = File.OpenText(CONFIG_FILE_PATH))
            {
                table = TOML.Parse(reader);
            }

            Cli.Verbosity = table["service"]["verbosity"].AsInteger;

            Port = table["service"]["port"].AsInteger;
            AllowTCP = table["service"]["allow_tcp"].AsBoolean;
            DBPath = table["service"]["db"]["db_file"].AsString;
            string setup_file_path = table["service"]["db"]["db_setup"].AsString;   
            DBSetupSQL = File.ReadAllText(setup_file_path);
            CachedNSTTL = table["simp_dns"]["cached_ns_ttl"].AsInteger;
            FallbackMinimumTTL = table["simp_dns"]["fallback_minimum_ttl"].AsInteger;
           
        }

        public Dictionary<string, Dictionary<ushort, string>> GetRootNameServers()
        {
            Dictionary<string, Dictionary<ushort, string>> rootNS = new();

            foreach(TomlTable node in table["simp_dns"]["root_ns"])
            {
                string domain = node["domain"].AsString;
                string ipv4 = node["1"].AsString;
                string ipv6 = node["28"].AsString;

                if(!rootNS.ContainsKey(domain))
                {
                    rootNS[domain] = new();
                }

                if (ipv4 != "")
                {
                    rootNS[domain][1] = ipv4;
                }

                if (ipv6 != "")
                {
                    rootNS[domain][28] = ipv6;
                }
            }

            return rootNS;
        }

        public (string, Dictionary<ushort, string>) GetLocalResolutions(string questionDomain)
        {
            Dictionary<ushort, string> resolutions = new();
            string matchedLocalDomain = "";

            foreach (TomlTable localResolutionEntry in table["simp_dns"]["local_resolution"])
            {
                string localDomain = localResolutionEntry["domain"].AsString;

                if (IsValidLocalResolution(questionDomain, localDomain))
                {
                    matchedLocalDomain = localDomain;
                    foreach (string key in localResolutionEntry.Keys)
                    {                        
                        if (ushort.TryParse(key, out ushort type))
                        {
                            resolutions.Add(type, localResolutionEntry[key].AsString);
                        }
                    }
                }
            }
            
            return (matchedLocalDomain, resolutions);
        }
        
        public bool IsValidLocalResolution(string questionName, string localName)
        {
            localName = localName.Replace("_", "*");

            questionName = questionName.ToLower();
            if (!questionName.EndsWith("."))
                questionName += ".";
        
            localName = localName.ToLower();
            if (!localName.EndsWith("."))
                localName += ".";
        

            if (questionName == localName || questionName.EndsWith("." + localName))
                return true;
        
            // Wildcard case (*.)
            if (localName.StartsWith("*."))
            {
                localName = localName.Substring(2);

                string[] questionParts = questionName.Split('.');

                // Including "" part (root)
                if (questionParts.Length >= 2)
                {
                    string questionWithoutFirstPart = string.Join(".", questionParts, 1, questionParts.Length - 1);
                
                    if (questionWithoutFirstPart == localName)
                        return true;
                }
            }
        
            return false;
        }
    }
}
