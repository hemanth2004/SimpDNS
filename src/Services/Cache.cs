using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Data.Sqlite;

namespace HMNT.SimpDNS
{
    public class Cache
    {
        public static Cache Instance = null;

        private readonly string _connectionString;
        private static int _cachedNSTTL; // TTL for cached Authoritative NSs
        
        private Config _config;
        public Cache()
        {
            if (Instance == null) { Instance = this; }

            _config = Config.Instance;

            _cachedNSTTL = _config.CachedNSTTL;
            _connectionString = $"Data Source={_config.DBPath ?? "dns_cache.db"}";
            Init(_config.DBSetupSQL);
        }
        
        private void Init(string dbSetup)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                
                var command = connection.CreateCommand();
                command.CommandText = dbSetup;
                command.ExecuteNonQuery();
            }

            EnsureRootNameservers();
        }
        
        #region Resource Records

        public void StoreResourceRecords(List<DnsResourceRecord> records)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                using (var transaction = connection.BeginTransaction())
                {
                    foreach (var record in records)
                    {
                        // Cli.Log($"Storing resource record for {record.RName} {record.RType} {record.RClass} {record.TTL}");
                        var command = connection.CreateCommand();
                        command.Transaction = transaction;
                        command.CommandText = @"
                            INSERT OR REPLACE INTO resource_records 
                            (domain_name, record_type, record_class, ttl, rdata, expiry)
                            VALUES (@domainName, @recordType, @recordClass, @ttl, @rdata, 
                                    datetime('now', '+' || @ttl || ' seconds'))";
                        
                        command.Parameters.AddWithValue("@domainName", record.RName.ToLower());
                        command.Parameters.AddWithValue("@recordType", record.RType);
                        command.Parameters.AddWithValue("@recordClass", record.RClass);
                        command.Parameters.AddWithValue("@ttl", record.TTL);
                        command.Parameters.AddWithValue("@rdata", record.RData);
                        
                        command.ExecuteNonQuery();
                    }
                    
                    transaction.Commit();
                }
            }
        }

        public bool TryGetResourceRecords(string domainName, ushort recordType, ushort recordClass, out List<DnsResourceRecord> records)
        {
            // Console.WriteLine("Requesting resource records for " + domainName + " " + recordType + " " + recordClass);
            
            records = new List<DnsResourceRecord>();
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT rdata, ttl, (strftime('%s', expiry) - strftime('%s', 'now')) as remaining_ttl 
                    FROM resource_records 
                    WHERE domain_name = @domainName 
                    AND record_type = @recordType 
                    AND record_class = @recordClass
                    AND expiry > datetime('now')";
                
                command.Parameters.AddWithValue("@domainName", domainName.ToLower());
                command.Parameters.AddWithValue("@recordType", recordType);
                command.Parameters.AddWithValue("@recordClass", recordClass);


                
                using (var reader = command.ExecuteReader())
                {
                    bool hasRecords = false;
                    
                    while (reader.Read())
                    {
                        hasRecords = true;
                        var rdata = (byte[])reader["rdata"];
                        var ttl = Convert.ToUInt32(reader["remaining_ttl"]);
                        
                        var record = new DnsResourceRecord
                        {
                            RName = domainName,
                            RType = recordType,
                            RClass = recordClass,
                            TTL = ttl,
                            RDLength = (ushort)rdata.Length,
                            RData = rdata
                        };
                        
                        records.Add(record);
                    }
                    
                    if (!hasRecords) {
                        using (var diagCommand = connection.CreateCommand()) {
                            diagCommand.CommandText = "SELECT COUNT(*) FROM resource_records WHERE domain_name = @domainName";
                            diagCommand.Parameters.AddWithValue("@domainName", domainName.ToLower());
                            var count = Convert.ToInt32(diagCommand.ExecuteScalar());
                        }
                    }
                    
                    return hasRecords;
                }
            }
        }
        
        #endregion
        
        #region Authoritative Nameservers

        // This is a redundant table because we can get the same info from the resource_records table (type = NS)
        // but we store it here for quicker lookups because rdata is bytes

        public void StoreAuthoritativeNameserver(string domainName, string nameserver)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT OR REPLACE INTO authoritative_nameservers 
                    (domain_name, nameserver, last_used, expiry)
                    VALUES (@domainName, @nameserver, datetime('now'), datetime('now', '+' || @days || ' days'))";
                
                command.Parameters.AddWithValue("@domainName", domainName.ToLower());
                command.Parameters.AddWithValue("@nameserver", nameserver.ToLower());
                command.Parameters.AddWithValue("@days", _cachedNSTTL);
                
                command.ExecuteNonQuery();
            }
        }
        
        public List<string> GetAuthoritativeNameservers(string domainName)
        {
            var nameservers = new List<string>();
            
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT nameserver
                    FROM authoritative_nameservers
                    WHERE domain_name = @domainName
                    AND expiry > datetime('now')
                    ORDER BY last_used DESC";
                
                command.Parameters.AddWithValue("@domainName", domainName.ToLower());
                
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        nameservers.Add((string)reader["nameserver"]);
                    }
                }
            }
            
            return nameservers;
        }
        
        #endregion
                
        #region Negative Cache
        public void StoreNegativeCache(string domainName, ushort recordType, ushort recordClass, uint ttl)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT OR REPLACE INTO negative_cache 
                    (domain_name, record_type, record_class, expiry)
                    VALUES (@domainName, @recordType, @recordClass, datetime('now', '+' || @ttl || ' seconds'))";
                
                command.Parameters.AddWithValue("@domainName", domainName.ToLower());
                command.Parameters.AddWithValue("@recordType", recordType);
                command.Parameters.AddWithValue("@recordClass", recordClass);
                command.Parameters.AddWithValue("@ttl", ttl);
                
                command.ExecuteNonQuery();
            }
        }

        public bool IsNegativelyCached(string domainName, ushort recordType, ushort recordClass)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT 1 FROM negative_cache 
                    WHERE domain_name = @domainName 
                    AND record_type = @recordType 
                    AND record_class = @recordClass
                    AND expiry > datetime('now')";
                
                command.Parameters.AddWithValue("@domainName", domainName.ToLower());
                command.Parameters.AddWithValue("@recordType", recordType);
                command.Parameters.AddWithValue("@recordClass", recordClass);
                
                var result = command.ExecuteScalar();
                return result != null;
            }
        }
        
        #endregion
        

        public void RemoveExpiredRecords()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    DELETE FROM resource_records WHERE expiry <= datetime('now');
                    DELETE FROM negative_cache WHERE expiry <= datetime('now');
                    DELETE FROM authoritative_nameservers WHERE expiry <= datetime('now');
                ";
                
                command.ExecuteNonQuery();
            }
        }

        public void PrintAllAuthoritativeNameservers()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT *
                    FROM resource_records";
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        byte[] ipBytes = (byte[])reader["rdata"];
                        string ipAddress = new System.Net.IPAddress(ipBytes).ToString();
                        
                        Cli.Log($"Domain Name: {reader["domain_name"]}, IP Address: {ipAddress}");
                    }
                }
            }
        }

        private void PrintAllNegativeCache()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT * FROM negative_cache";
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Cli.Log($"Domain Name: {reader["domain_name"]}, Record Type: {reader["record_type"]}, Record Class: {reader["record_class"]}, Expiry: {reader["expiry"]}");
                    }
                }
            }
        }

        public void EnsureRootNameservers()
        {
            bool hasRootNameservers = false;
            // PrintAllAuthoritativeNameservers();
            // PrintAllNegativeCache();

            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT COUNT(*) FROM authoritative_nameservers 
                    WHERE domain_name = '.' AND expiry > datetime('now')";
                
                var result = command.ExecuteScalar();

                // Atleast 1 root ns in cache
                hasRootNameservers = Convert.ToInt32(result) > 0;
            }
            
            if (!hasRootNameservers)
            {
                Cli.Log("Root NS records not found in cache. \nAdding them back from config...");
                
                try 
                {
                    var rootNameservers = Config.Instance.GetRootNameServers();
                
                    foreach (var entry in rootNameservers)
                    {
                        string nameserver = entry.Key;
                        var records = entry.Value;
                        
                        // . => root domain
                        StoreAuthoritativeNameserver(".", nameserver);
                        
                    
                        List<DnsResourceRecord> resourceRecords = new List<DnsResourceRecord>();
                        foreach (var recordEntry in records)
                        {
                            ushort recordType = recordEntry.Key;
                            string ipAddress = recordEntry.Value;
                            
                            byte[] rdata;
                            if (recordType == Dns.TypeA)
                            {
                                rdata = System.Net.IPAddress.Parse(ipAddress).GetAddressBytes();
                            }
                            else if (recordType == Dns.TypeAAAA)
                            {
                                rdata = System.Net.IPAddress.Parse(ipAddress).GetAddressBytes();
                            }
                            else
                                continue;
                            

                            DnsResourceRecord record = new DnsResourceRecord
                            {
                                RName = nameserver,
                                RType = recordType,
                                RClass = Dns.ClassINET,
                                TTL = Int32.MaxValue,
                                RDLength = (ushort)rdata.Length,
                                RData = rdata
                            };
                            
                            resourceRecords.Add(record);
                        }
                        
                        // Also store as an actual resource record
                        if (resourceRecords.Count > 0)
                        {
                            StoreResourceRecords(resourceRecords);
                        }
                    }
                }
                catch (Exception e)
                {
                    Cli.LogError($"Error adding root NS records to cache: {e.Message}");
                }
            }
        }
  
    }
} 