using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Collections.Generic;
using Tommy;

namespace HMNT.SimpDNS
{
    public class DnsHandler
    {
        public Cache cache;
        public Config config;

        public DnsHandler()
        {
            this.cache = Cache.Instance;
            this.config = Config.Instance;
        }

        public byte[] Handle(byte[] reqBytes, IPEndPoint ipEndpoint)
        {

            using (MemoryStream ms = new MemoryStream(reqBytes))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                // First parse request packet
                DnsPacket requestPacket = null;
                try {
                    requestPacket = DnsPacket.DeserializeFrom(reqBytes);
                }
                catch(Exception e)
                {
                    // If DNS format is not correct
                    Cli.LogError($"Request from {ipEndpoint} - {e.Message} - ERROR PARSING PACKET");
                    
                    DnsPacket formatErrorResponsePacket = new DnsPacket();
                    formatErrorResponsePacket.Header.Flags = (ushort)(Dns.FlagQR | Dns.FlagRA);
                    formatErrorResponsePacket.Header.SetResponseCode(Dns.RCodeFormatError);
                    
                    return DnsPacket.SerializeToBytes(formatErrorResponsePacket);
                }


                // Prep response packet regardless of result
                ushort responseCode = Dns.RCodeNoError;
                DnsPacket responsePacket = new DnsPacket();
                responsePacket.Questions = requestPacket.Questions;
                responsePacket.Header.TransactionID = requestPacket.Header.TransactionID;
                responsePacket.Header.QuestionCount = (ushort)responsePacket.Questions.Count;

                // Check requested operation

                // Handle DNS server status request
                if (requestPacket.Header.GetOpCode() == Dns.OpCodeStatus)
                {
                    Cli.Log($"[STATUS] from {ipEndpoint} - {requestPacket.Questions[0].QName}." );
                    
                    // Set response packet flags
                    ushort flags = Dns.FlagQR; // Enable response flag
                    flags |= Dns.FlagRA;  // Recursion available cos this is a recursive DNS server

                    responsePacket.Header.SetResponseCode(responseCode);
                    responsePacket.Header.Flags = flags;
                    responsePacket.Header.AnswerRecordCount = 0;
                    responsePacket.Header.AuthorityCount = 0;
                    responsePacket.Header.AdditionalRecordCount = 0;

                    return DnsPacket.SerializeToBytes(responsePacket);
                }
                // Handle DNS query
                else if (requestPacket.Header.GetOpCode() == Dns.OpCodeQuery)
                {
                    bool __serverFailure = false;

                    Cli.Log($"[QUERY] from {ipEndpoint} - {requestPacket.Questions[0].QName}." );                

                    ResolutionContext context = new ResolutionContext();
                    try 
                    {
                        // Multiple questions are supported by ordering answers in the same order as the questions
                        // The ambiguity of answer-to-question mapping is left to the client as per the DNS spec
                        foreach(DnsQuestionRecord question in requestPacket.Questions)
                        {
                            var (answers, authority, additional) = DnsResolver.ResolveQuestion(question, context);

                            if (context.failed) { context.lastQuestion = question.QName; break; }

                            responsePacket.Answers.AddRange(answers);
                            responsePacket.Authority.AddRange(authority);
                            responsePacket.Additional.AddRange(additional);
                        }

                        // If even one domain was not found, set NXDomain rcode
                        // NXDomain can only be used by authoritative servers and servers with negative cache
                        if (context.failed)
                        {
                            Cli.LogError($"No such domain - {context.lastQuestion}\n");
                            responseCode = Dns.RCodeNXDomain;
                        }
                    }
                    catch(Exception e)
                    {
                        __serverFailure = true;
                        Cli.LogError($"Resolution failed (Server Failure): {e.Message}");
                        responseCode = Dns.RCodeServerFailure;
                    }
                    
                    // Check for server failure before logging successful resolution
                    // Regardless of whether we actually found an answer or not
                    if (!__serverFailure) { Cli.Log("Resolved request query.", 2); }

                    context.responseCode = responseCode;
                    Cli.Log(context.ToString(), 2);

                    
                    ushort flags = Dns.FlagQR;
                    flags |= Dns.FlagRA;  // Recursion available because this is a recursive DNS server
                    responsePacket.Header.SetResponseCode(responseCode);
    
                    responsePacket.Header.AnswerRecordCount = (ushort)responsePacket.Answers.Count;
                    responsePacket.Header.AuthorityCount = (ushort)responsePacket.Authority.Count;
                    responsePacket.Header.AdditionalRecordCount = (ushort)responsePacket.Additional.Count;
                    responsePacket.Header.Flags = flags;

                    return DnsPacket.SerializeToBytes(responsePacket);
                }
                else
                {
                    Cli.LogError($"Unsupported operation code: {requestPacket.Header.GetOpCode()}");
                    responseCode = Dns.RCodeNotImplemented;

                    ushort flags = Dns.FlagQR;
                    flags |= Dns.FlagRA;
                    responsePacket.Header.SetResponseCode(responseCode);

                    return DnsPacket.SerializeToBytes(responsePacket);
                }
            }
        }
    }
}