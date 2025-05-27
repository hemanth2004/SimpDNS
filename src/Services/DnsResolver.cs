namespace HMNT.SimpDNS
{
    public static class DnsResolver
    {
        public static readonly int MAX_DEPTH = 10; // max depth
        public static readonly int MAX_ITERATIONS = 20; // max "breadth" per depth

        public static Cache cache;
        public static Config config;

        public static void Initialize(Cache cache, Config config)
        {
            if (cache == null || config == null)
            {
                DnsResolver.cache = Cache.Instance;
                DnsResolver.config = Config.Instance;
            }
        }

        // Entry point for resolving a question
        public static (List<DnsResourceRecord>, List<DnsResourceRecord>, List<DnsResourceRecord>) ResolveQuestion(DnsQuestionRecord question, ResolutionContext context)
        {
            Initialize(cache, config);

            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>();

            // 1. Check cache for address resolution
            if (cache.TryGetResourceRecords(question.QName, question.QType, question.QClass, out List<DnsResourceRecord> records) && records.Count > 0)
            {
                context.foundInCache = true;
                List<DnsResourceRecord> nsRecords = new List<DnsResourceRecord>();
                cache.TryGetResourceRecords(question.QName, Dns.TypeNS, Dns.ClassINET, out nsRecords);
                cache.TryGetResourceRecords(question.QName, Dns.TypeAAAA, Dns.ClassINET, out additionalRecords);

                return (records, nsRecords, additionalRecords);
            }

            // 2. Check local resolutions
            (string localDomain, Dictionary<ushort, string> relevantLocalResolutions) = config.GetLocalResolutions(question.QName);
            if (relevantLocalResolutions.TryGetValue(question.QType, out string localResolution))
            {
                context.foundInLocalResolutions = true;

                foreach (ushort type in relevantLocalResolutions.Keys)
                {
                    if (type != question.QType)
                    {
                        additionalRecords.Add(Utils.CreateFromLocalResolution(relevantLocalResolutions[type], type, question.QName));
                    }
                }

                return (
                    new List<DnsResourceRecord> { Utils.CreateFromLocalResolution(localResolution, question.QType, question.QName) },
                    new List<DnsResourceRecord>(),
                    additionalRecords
                );
            }


            // 3. Check negative cache
            if (cache.IsNegativelyCached(question.QName, question.QType, question.QClass))
            {
                context.foundInNegativeCache = true;
                return (
                    new List<DnsResourceRecord>(),
                    new List<DnsResourceRecord>(),
                    new List<DnsResourceRecord>()
                );
            }

            // 4. Perform recursive resolution
            return PerformRecursiveResolution(question, context);
        }

        

        // Start recursive resolution
        private static (List<DnsResourceRecord>, List<DnsResourceRecord>, List<DnsResourceRecord>) PerformRecursiveResolution(DnsQuestionRecord question, ResolutionContext context, int depth = 0)
        {
            if (depth > MAX_DEPTH)
            {
                Cli.LogError($"Maximum depth reached: {depth}");
                context.failed = true;
                return (new List<DnsResourceRecord>(), new List<DnsResourceRecord>(), new List<DnsResourceRecord>());
            }

            // Determine our best/closest starting point for beginning the resolution
            List<string> nameservers = GetStartingNameservers(question.QName, context);
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>();
            
            return ResolveUsingNameservers(question, nameservers, context, additionalRecords, depth);
        }

        // Recursive resolution
        // Depth and iteration both are needed for preventing infinite loops
        private static (List<DnsResourceRecord>, List<DnsResourceRecord>, List<DnsResourceRecord>) ResolveUsingNameservers(
            DnsQuestionRecord question, 
            List<string> nameservers, 
            ResolutionContext context, 
            List<DnsResourceRecord> additionalRecords,
            int depth,
            int iteration = 1)
        {
            if (iteration > MAX_ITERATIONS)
            {
                context.failed = true;
                return (new List<DnsResourceRecord>(), new List<DnsResourceRecord>(), additionalRecords);
            }

            Cli.Log($"Iteration {iteration}", 2);


            // Try each NS given to us           
            foreach (string nameserver in nameservers)
            {
                // Resolve the NS to an IP - regardless of means
                List<System.Net.IPAddress> nameserverIPs = ResolveNameserverIP(nameserver, context, depth + 1);
                if (nameserverIPs.Count == 0) continue; // next NS
                
                Cli.Log($"Trying nameserver: {nameserver}", 2);
                
                // For each IP of an NS that we are given at a recursive level
                foreach (var ip in nameserverIPs)
                {                    
                    var (response, error) = InternalDnsClient.QueryNameserver(ip, question);
                    if (error != null) continue;
                    context.externalRequestCount++;

                    Cli.Log($"Response: {response.ToString()}", 3);

                    // Check for NXDOMAIN and authoritative answer
                    if (response.Header.GetResponseCode() == Dns.RCodeNXDomain && 
                        (response.Header.Flags & Dns.FlagAA) != 0)
                    {
                        context.failed = true;
                        cache.StoreNegativeCache(question.QName, question.QType, question.QClass, 60);
                        return (new List<DnsResourceRecord>(), response.Authority, response.Additional);
                    }
                    
                    // else store the records of the response
                    cache.StoreResourceRecords(response.Authority);
                    cache.StoreResourceRecords(response.Additional);

                    // FINALLY found our answer
                    if (response.Answers.Count > 0)
                    {
                        cache.StoreResourceRecords(response.Answers);

                        List<DnsResourceRecord> nsRecords = new List<DnsResourceRecord>();
                        cache.TryGetResourceRecords(question.QName, Dns.TypeNS, Dns.ClassINET, out nsRecords);
                        cache.TryGetResourceRecords(question.QName, question.QType == Dns.TypeAAAA ? Dns.TypeA : Dns.TypeAAAA, 
                                                                Dns.ClassINET, out additionalRecords);

                        response.Authority.AddRange(nsRecords);
                        response.Additional.AddRange(additionalRecords);

                        return (response.Answers, response.Authority, response.Additional);
                    }
                    

                    // Else check if we got new nameservers to follow
                    if (response.Authority.Count > 0 && response.Authority[0]?.RName != null)
                    {
                        List<string> newNameservers = Utils.ExtractNameservers(response.Authority, response.FullPacketBytes);
                        if (newNameservers.Count > 0)
                        {
                            additionalRecords.AddRange(response.Additional);
                                
                            string authZone = response.Authority[0].RName;
                            foreach (var ns in newNameservers)
                            {
                                cache.StoreAuthoritativeNameserver(authZone, ns);
                            }
                                
                            // Recursively resolve with new nameservers
                            return ResolveUsingNameservers(question, newNameservers, context, additionalRecords, depth, iteration + 1);
                        }
                    }
                }
            }
            
            // No such domain found
            context.failed = true;
            return (new List<DnsResourceRecord>(), new List<DnsResourceRecord>(), additionalRecords);
        }

        private static List<System.Net.IPAddress> ResolveNameserverIP(string nameserver, ResolutionContext context, int currentDepth)
        {
            // List to return
            List<System.Net.IPAddress> ips = new List<System.Net.IPAddress>();
            
            // 1. Check cache
            if (cache.TryGetResourceRecords(nameserver, Dns.TypeA, Dns.ClassINET, out List<DnsResourceRecord> aRecords))
            {   
                foreach (var record in aRecords)
                {
                    ips.Add(new System.Net.IPAddress(record.RData));
                }
            }
            // Doesn't matter if it's A or AAAA
            // We just need a way to contact the authority of the domain
            if (cache.TryGetResourceRecords(nameserver, Dns.TypeAAAA, Dns.ClassINET, out List<DnsResourceRecord> aaaaRecords))
            {
                foreach (var record in aaaaRecords)
                {
                    ips.Add(new System.Net.IPAddress(record.RData));
                }
            }
            
            // 2. Recursive resolution
            if (ips.Count == 0)
            {
                DnsQuestionRecord nsQuestion = new DnsQuestionRecord
                {
                    QName = nameserver,
                    QType = Dns.TypeA,
                    QClass = Dns.ClassINET
                };
                



                var (nsRecords, _, _) = PerformRecursiveResolution(nsQuestion, context, currentDepth);
                foreach (var nsRecord in nsRecords)
                {
                    if (nsRecord.RData != null && nsRecord.RData.Length > 0)
                    {
                        ips.Add(new System.Net.IPAddress(nsRecord.RData));
                    }
                }
                // Also try IPv6
                nsQuestion.QType = Dns.TypeAAAA;
                var (nsRecords6, _, _) = PerformRecursiveResolution(nsQuestion, context, currentDepth);
                foreach (var nsRecord in nsRecords6)
                {
                    if (nsRecord.RData != null && nsRecord.RData.Length > 0)
                    {
                        ips.Add(new System.Net.IPAddress(nsRecord.RData));
                    }
                }



            }
            
            return ips;
        }


        private static List<string> GetStartingNameservers(string domain, ResolutionContext context)
        {
            string closestDomain = FindClosestCachedAuthoritativeNameserver(domain);
            context.bestStartingPoint = closestDomain;
            
            if (!string.IsNullOrEmpty(closestDomain))
            {
                Cli.Log($"Closest cached domain: {closestDomain}", 2);
                var cachedNameservers = cache.GetAuthoritativeNameservers(closestDomain);
                if (cachedNameservers.Count > 0)
                {
                    return new List<string>(cachedNameservers);
                }
            }
            else { context.bestStartingPoint = "."; }
            
            // Fallback to root servers
            return new List<string>(Dns.RootNameservers);
        }

        // Strategy: Search cached NS table for the given domain
        // Go from "specific" to "general" and check each for an authoritative nameserver
        private static string FindClosestCachedAuthoritativeNameserver(string domain)
        {
            string[] parts = domain.Split('.');
            
            for (int i = 0; i < parts.Length; i++)
            {
                string testDomain = string.Join(".", parts, i, parts.Length - i);
                if (cache.GetAuthoritativeNameservers(testDomain).Count > 0)
                {
                    return testDomain;
                }
            }
            return null;
        }
    }

    [System.Serializable]
    public class ResolutionContext
    {
        public ushort responseCode;
        public string bestStartingPoint;

        // Question at which we failed
        public string lastQuestion { get; set; } = string.Empty;
        public bool failed;

        public bool foundInCache;
        public bool foundInLocalResolutions;
        public bool foundInNegativeCache;
        public uint externalRequestCount;        

        public override string ToString()
        {
            string result = "";
            if (failed) { result = "FAIL (NO SUCH DOMAIN)"; }
            else if (foundInCache) { result = "SUCCESS (CACHE HIT)"; }
            else if (foundInLocalResolutions) { result = "SUCCESS (LOCAL RESOLUTION)"; }
            else if (foundInNegativeCache) { result = "SUCCESS (NEGATIVE CACHE)"; }
            else { result = "SUCCESS (RECURSIVE RESOLUTION)"; }
            
            return $"RESULT:        {result}\n" +
                    $"RES CODE:      {responseCode}\n" +
                    $"IN CACHE:      {foundInCache}\n" +
                    $"IN LOCAL:      {foundInLocalResolutions}\n" +
                    $"IN NEG CACHE:  {foundInNegativeCache}\n" +
                    $"EXTERN NS REQ: {externalRequestCount}\n";
        } 
    }
}
