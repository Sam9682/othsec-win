﻿using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Collections;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Threading;
using System.Reflection.Metadata;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Diagnostics;

namespace othsec
{

    //******************************************************************************************************************************//
    //******************************************************************************************************************************//
    // class Program
    //    main() entry point
    //******************************************************************************************************************************//
    //******************************************************************************************************************************//
    static class Program
    {
        static public string IPSvrBeeWoo;
        static public string IPSvrLambdaLocalization;
        static public string IPSvrKinesisFirehose;
        public static ManualResetEvent allDone = new ManualResetEvent(false);
        public static string ServerCertificatePfx = "./certificat.pfx";
        public static string ServerCertificatePfx2 = "./localhost.pfx";
        public static string ServerKey = "./key.txt";
        public static X509Certificate serverCertificate = null;
        public static bool SSL_ENABLED = true;
        private static string sslKey =
            "MIIKUAIBAzCCChYGCSqGSIb3DQEHAaCCCgcEggoDMIIJ/zCCBJcGCSqGSIb3DQEH" +
            "BqCCBIgwggSEAgEAMIIEfQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQI90/u" +
            "uP7KiKICAggAgIIEUPNFftNYVythxHYXaLYG76TrCPxsGV87XLUPvTdUgyscCUan" +
            "4NlizSpugrNA8Hl4U90XOSA01MSxc153ZmE9VliY5bmbioz+wlwuerAnL6FClRKA" +
            "3tagCS7GNUGb9VhOwoP9MO3JfysD8Nz6GbwnWNbB1vLL8dH5X6Zxt+LI28IxRjd2" +
            "xEg7ZUC4yZiDMjTK1WbL8ql9u/eD09KslKfVFy+ESXUps2IHlZ2roqAvqjPXMrwR" +
            "QLOTds8vsZtkqxwKuLfXYz7oG68G/rGRavtpdGZY+c94fkg7LbiSGYMc26Ws4JbR" +
            "tzU4PGWCxvmIKP5Ih45iflbxJybZrr73nWxP/2sXlZdMxuqbrP5/NAuW55gVd5qT" +
            "5Pd+WgEe/6XTSmz4b3CPPo3YFJq0ZaNOWICMPHxhlalkqqYahNeK/oh0wALXq/I3" +
            "BlXB2EVpdfBrceVRa2hrieiAoLDPYOknrJTu6AUDpu9DIHibIWb6+sI5hah7i5H+" +
            "4t5FoiWpRcXcLVFkxWVrTZ73x/tsDlTorwY2zjtLCsRXifdGyGoA/WWM+2fK/G/M" +
            "50X+HKXJJCu0J7Pd1447O2vH23K8nM/ECDpYtMzK/ghOoHTk3TqkQzmFZ0MTH1eJ" +
            "vFnNBXWkOOLfai8bdOIehkv8+hIkw5c93sznECZcvf9yssXfbzozKPRJ/A/18BJ1" +
            "NXWU5vivDRYsMZ7qAnCD7vBkGaPqXgtYoR342imVuyCNjV5470dR3vZaao1LQkGX" +
            "5oPRfRlG5PrKmAxL1/u8bHeHo1UKyPgAjCW+b4cE5nydbceJ3y9B0jjNOMwUuHc4" +
            "iwfe0Re/CGeDRkP1LlcuEI0xPY1CTAbDhJICbj2rGoueJQTH8D2uzIQIebio/bd7" +
            "M7dbSYh9CK6bN6KCgfVC2jBo3Q5BK354CRIw6sbiRx1p2k74ThQtVLk0uTEB/qQI" +
            "32bkSrM3Sv/e6u05jI0XRC+roY5auW1vgr4jJvs6sa+Ex8ufscQfxvkHTc2bMi9L" +
            "BwZag5uOf8SYScUr/lfHd9zxBMXldp6sCe97RKF7hO8pqks0zo+uP7wLkwKuugTD" +
            "bKGN3E85jERsqJe+TgsjchdMxHvcxrK6NvOAjKLtXw6mZhFDTevupJpWQPkPzp7m" +
            "7mQUhZ+GkgeNYhJmSaM6g6NIvnWaincyIv7hUs5yh7K0iKJ/JylwiWUJaoFZg/3Z" +
            "DhssJfdoRITsge4xe3pK5NE2y8MnExI5NWWh+2KLYb48M8jwfiNU5I0KPjh/UQRa" +
            "pTTaOf2WL6jA3NcfgOmYqQrVYix4Yrb/NaY6j8Zeb8n7MNuAh6YOe6iMbt6h81WZ" +
            "Y8Md36/MqUN0YngvslQvXMeL491EIoPTk5rSCCmc3uYMoKqYyPIFaaurptmVZH6p" +
            "8G0cqGn0oBQMW8NobVLE2USW6ddeecnNaKLsJbxana+uCnE2ifJ0p/5JSDTdOCOz" +
            "Sp+j4aUSfqx2jXtO+DCCBWAGCSqGSIb3DQEHAaCCBVEEggVNMIIFSTCCBUUGCyqG" +
            "SIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAg8RfzcIG94kgICCAAE" +
            "ggTIMkHvFpnukgwsxhZB20tX27Tlynjsh776R1R+228634qGV6KxQj4BOTqhEHYq" +
            "0HnkMoyJp++RP891DcHiRZ8zvLwpRNfY1YTar7Ktcnioq5u0Cfni+2rHDUvAQ6Jf" +
            "AkfncNtRDKJL/MZlHAJ/8wn1XXSBIbwN7AiCcpzMrQkb+DS2IYbvwWTQF8ZlIsAP" +
            "yk9Wu/BmDsuQRF4ZZZ/f5UReBthWJjsGRobC4DZEc5zallhjMKfDRBnjigJ9mRGM" +
            "JMqwLnA1D777KwD2ID0zxy5WGZIek88pp+viGVrBhewbMPvIZtirklsjp+OfDxgk" +
            "tLhNtYZGZlsAWRs0rMUwM9d2mWNttR2Irj3cGy6p6dUykg+u92U9DDP417BIZQ0W" +
            "HaIFEXsiVBbDGxXU4wGZvD51/NoxQpqkNRw0wf2XNPaUVwGaUkMdwbyygDqLy63R" +
            "O8ZAe0Nn7uBgUz104Z9usJSZW/uomeZgVsX8+x2a1mW2r5TVhiYFBj3t75qm/MCw" +
            "bye8SeDK8XvgkvPlVo/+X86Vc55Fd9FFppCokOMPghI+K+osaNFs2amVHkXs3cKK" +
            "SXW4NTd6W7o6JC4yeamy4CGDyOdPmJuWa+r2XPx3VPwEs247tbg6W3nSr9PIWw5a" +
            "PZzmNwCiOdlu8DY3IXNTBtYn7PeDTYtmTHnZyXd0mbfzEIHFn41f0avDErH2osIz" +
            "i0eSnGYih7YFm1rGsa8ade7JtHXcS5gNztNpkuizqnod9fDX8ede8q5QLd5Fn0UH" +
            "TJXlltD7dTQHStAucFkoXBJQ5/9Q1R8ZhcPuf6dFnOxffY56Pk/kNs3slVtlQBhg" +
            "NtboLhhs8W9oHfyn7PZ/G9N9Feg5q/E8BRtMye/ff2q8PYm8xYUot7A/Em/OBSOG" +
            "yMXJQyuoP+fc9C+qT4FRiS2U8OLm/5cFfYbmT1uQ295Ox/kRF/CPh2ozkTGT11Ys" +
            "i62BMczQCrm24DaTu4CUMHYHDmcCMWlqD5GjA4uOh3vXAGiDGYZUiIym+kvLoZzv" +
            "UG1zXZdfKaFxbGECnrPTdp+UeraKa3vbHH9oyr4FRmj2+tuVvDHLJuP2dHuj3HVG" +
            "1D7Qo6BPDc1u8b3lpPuxuvge+gNr+BfAMNy/fJGiuC/AQfWQgqAnwM/sFe9UD11M" +
            "a74zVgPnAFDHnGDcJpjOHIsTbFYzGqVsCdY1eI3swGR+7fH3IGMjn/BPL9QND2jY" +
            "OmTElP0adFbxcpAZnyFS/iASgTx7UxOCuRsu7eyL6nbaE2gtH/iVs40IIgpD9oBp" +
            "BjWnGxA9PjI418hnMGu5X2x3GKT/gXdZ4PBOld9eDmBR5HCR/Ni4eavpI5tV7H95" +
            "i9fGlvq8DjYr0pZmquQ2Mgs+ABxMBdrTvgT8ia9xpWcU89Q2ihus0pmrq1wSNAbp" +
            "hwSArmxL0sTuwCFeBpvG5W+7rplgjybV8rYxjAMP/fAmpuN35u4IUr1/VJEazBTv" +
            "DFaNNrqPLG89VR2u93aKvkZ8UgYoH5cetiS4wST4kzoRYKLGrZS1wVQrjQ+SD9en" +
            "1nwHsmdJ+TEuk+3x3yqm851wA42G7AseXlBzwylGxqczg1kYUIDgHSeWBdbPNo7p" +
            "6KqecPl1upZMql6kgIEZmMNT9P2Fow8s3X9lMUQwHQYJKoZIhvcNAQkUMRAeDgBT" +
            "AHMAbABDAGUAcgB0MCMGCSqGSIb3DQEJFTEWBBSZhgRZGD8VPUAzYZrUGNw7Asm1" +
            "4zAxMCEwCQYFKw4DAhoFAAQU9e1pj3KduXtEMQmDin+RgaDNMRUECHGtAPRuyKxT" +
            "AgIIAA==";

        private static IDictionary<string, string> _mimeTypeMappings = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase) {
        #region extension to MIME type list
        {".asf", "video/x-ms-asf"},
        {".asx", "video/x-ms-asf"},
        {".avi", "video/x-msvideo"},
        {".bin", "application/octet-stream"},
        {".cco", "application/x-cocoa"},
        {".crt", "application/x-x509-ca-cert"},
        {".css", "text/css"},
        {".deb", "application/octet-stream"},
        {".der", "application/x-x509-ca-cert"},
        {".dll", "application/octet-stream"},
        {".dmg", "application/octet-stream"},
        {".ear", "application/java-archive"},
        {".eot", "application/octet-stream"},
        {".exe", "application/octet-stream"},
        {".flv", "video/x-flv"},
        {".gif", "image/gif"},
        {".hqx", "application/mac-binhex40"},
        {".htc", "text/x-component"},
        {".htm", "text/html"},
        {".html", "text/html"},
        {".ico", "image/x-icon"},
        {".img", "application/octet-stream"},
        {".iso", "application/octet-stream"},
        {".jar", "application/java-archive"},
        {".jardiff", "application/x-java-archive-diff"},
        {".jng", "image/x-jng"},
        {".jnlp", "application/x-java-jnlp-file"},
        {".jpeg", "image/jpeg"},
        {".jpg", "image/jpeg"},
        {".js", "application/x-javascript"},
        {".mml", "text/mathml"},
        {".mng", "video/x-mng"},
        {".mov", "video/quicktime"},
        {".mp3", "audio/mpeg"},
        {".mpeg", "video/mpeg"},
        {".mpg", "video/mpeg"},
        {".msi", "application/octet-stream"},
        {".msm", "application/octet-stream"},
        {".msp", "application/octet-stream"},
        {".pdb", "application/x-pilot"},
        {".pdf", "application/pdf"},
        {".pem", "application/x-x509-ca-cert"},
        {".pl", "application/x-perl"},
        {".pm", "application/x-perl"},
        {".png", "image/png"},
        {".prc", "application/x-pilot"},
        {".ra", "audio/x-realaudio"},
        {".rar", "application/x-rar-compressed"},
        {".rpm", "application/x-redhat-package-manager"},
        {".rss", "text/xml"},
        {".run", "application/x-makeself"},
        {".sea", "application/x-sea"},
        {".shtml", "text/html"},
        {".sit", "application/x-stuffit"},
        {".swf", "application/x-shockwave-flash"},
        {".tcl", "application/x-tcl"},
        {".tk", "application/x-tcl"},
        {".txt", "text/plain"},
        {".war", "application/java-archive"},
        {".wbmp", "image/vnd.wap.wbmp"},
        {".wmv", "video/x-ms-wmv"},
        {".xml", "text/xml"},
        {".xpi", "application/x-xpinstall"},
        {".zip", "application/zip"},
        #endregion

        };

        //******************************************************************************************************************************//
        // Program::RSACryptoServiceProvider()
        //******************************************************************************************************************************//
        static private RSACryptoServiceProvider CreateRSAFromFile(string filename)
        {
            byte[] pvk = null;
            using (var fs = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                pvk = new byte[fs.Length];
                fs.Read(pvk, 0, pvk.Length);
            }

            var rsa = new RSACryptoServiceProvider();
            rsa.ImportCspBlob(pvk);

            return rsa;
        }

        //******************************************************************************************************************************//
        // Program::Main()
        //******************************************************************************************************************************//
        static void Main()
        {

            try
            {
                Program.serverCertificate = new X509Certificate(Program.ServerCertificatePfx2, "Asbaasba1234!");
                
                //Program.serverCertificate = new X509Certificate2(Program.ServerCertificatePfx, "Asbaasba1"); 
                //Program.serverCertificate = new X509Certificate2(Convert.FromBase64String(sslKey), "Asbaasba1", X509KeyStorageFlags.Exportable);

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                Console.WriteLine("INFO: YES MAN !!! X509 certificate '{0}' successfully loaded in memory for HTTPS !", Program.ServerCertificatePfx2);
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: ({0}): X509Certificate2.CreateFromCertFile = " + ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
                return;
            }

            // we are only listening to IPv4 interfaces
            var IPv4Addresses = Dns.GetHostEntry(Dns.GetHostName())
                .AddressList.Where(al => al.AddressFamily == AddressFamily.InterNetwork)
                .AsEnumerable();
            TcpListener server = new TcpListener(IPAddress.Loopback, 20508); //+IPAddress.Loopback
            TcpClient clientAccepted = default(TcpClient);
            string beewoo_domaine_name = "beewoo.fr";
            string beewoo_lambda_functions = "lambda.eu-west-1.amazonaws.com";
            string beewoo_kinesis_functions = "firehose.eu-west-1.amazonaws.com";

            try
            {
                IPAddress[] addresslist = Dns.GetHostAddresses(beewoo_domaine_name);
                IPSvrBeeWoo = addresslist[0].ToString();

                IPAddress[] addresslist2 = Dns.GetHostAddresses(beewoo_lambda_functions);
                IPSvrLambdaLocalization = addresslist2[0].ToString();

                IPAddress[] addresslist3 = Dns.GetHostAddresses(beewoo_kinesis_functions);
                IPSvrKinesisFirehose = addresslist3[0].ToString();

                Console.WriteLine("INFO: WEB OTHSEC address server is Dns.GetHostAddresses('{0}') = {1}", beewoo_domaine_name, IPSvrBeeWoo);
                Console.WriteLine("INFO: KINESIS address server is Dns.GetHostAddresses('{0}') = {1}", beewoo_kinesis_functions, IPSvrKinesisFirehose);
            }
            catch (Exception)
            {
                Console.WriteLine("WARNING: WEB OTHSEC {0} is not reachable !", beewoo_domaine_name);
            }

            try
            {
                server.Start();

                Console.WriteLine("INFO: LOCAL WEBSOCKET SERVER started {0}:20508", IPAddress.Loopback);
                if (IPSvrBeeWoo != null)
                {
                    Console.WriteLine("INFO: Waiting for webrowser connection: Launch https://beewoo.fr then 'Capture Internet Traffic'");
                    Console.WriteLine("INFO:                                   Launch https://localhost:20508 for local testing purpose");
                }
                else
                {
                    Console.WriteLine("INFO: Waiting for webrowser connection: Launch https://localhost:20508 for local testing purpose (beewoo.fr down ?)");
                }
                int nbrConn = 0;

                while (true)
                {
                    clientAccepted = server.AcceptTcpClient();

                    handleClinet client = new handleClinet();
                    client.StartClient(clientAccepted, Convert.ToString(nbrConn), clientAccepted.Client.RemoteEndPoint.ToString());
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("EXCEPTION ({0}): "+ e.ToString(), (int)(new StackTrace(e, true)).GetFrame(0).GetFileLineNumber());
            }
            finally
            {
                clientAccepted.Close();
                server.Stop();
            }
        }


        //******************************************************************************************************************************//
        // Program::ToProtocolString()
        //    details at http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        //******************************************************************************************************************************//
        public static string ToProtocolString(this byte b)
        {
                switch (b)
                {
                    case 1: return "ICMP";
                    case 6: return "TCP";
                    case 17: return "UDP";
                    default: return "#" + b.ToString();
                }
        }

        //******************************************************************************************************************************//
        // Program::ToFlagString()
        //******************************************************************************************************************************//
        public static string ToFlagString(this ushort b)
        {
            string flags = "";

            int[] lflags = new int[1] { b >> 8};
            BitArray lBit = new BitArray(lflags);
            //PrintBits(lBit);

            // U Urgent Flag 
            int[] lmaskU = new int[1] { 32 };
            BitArray lBitmaskU = new BitArray(lmaskU);
            // A flags
            int[] lmaskA = new int[1] { 16 };
            BitArray lBitmaskA = new BitArray(lmaskA);
            // P flags
            int[] lmaskP = new int[1] { 8 };
            BitArray lBitmaskP = new BitArray(lmaskP);
            // R flags
            int[] lmaskR = new int[1] { 4 };
            BitArray lBitmaskR = new BitArray(lmaskR);
            // S flags
            int[] lmaskS = new int[1] { 2 };
            BitArray lBitmaskS = new BitArray(lmaskS);
            // F flags
            int[] lmaskF = new int[1] { 1 };
            BitArray lBitmaskF = new BitArray(lmaskF);

            int[] resuU = new int[1];
            BitArray lBitU = new BitArray(lBit);
            lBitU.And(lBitmaskU).CopyTo(resuU, 0);

            int[] resuA = new int[1];
            BitArray lBitA = new BitArray(lBit);
            lBitA.And(lBitmaskA).CopyTo(resuA, 0);

            int[] resuP = new int[1];
            BitArray lBitP = new BitArray(lBit);
            lBitP.And(lBitmaskP).CopyTo(resuP, 0);

            int[] resuR = new int[1];
            BitArray lBitR = new BitArray(lBit);
            lBitR.And(lBitmaskR).CopyTo(resuR, 0);

            int[] resuS = new int[1];
            BitArray lBitS = new BitArray(lBit);
            lBitS.And(lBitmaskS).CopyTo(resuS, 0);

            int[] resuF = new int[1];
            BitArray lBitF = new BitArray(lBit);
            lBitF.And(lBitmaskF).CopyTo(resuF, 0);
            //Console.WriteLine("{0}", resu[0].ToString());

            if (resuU[0] >0)
            {
                flags = flags + "U ";
            }
            else
            { 
                flags = flags + "- "; 
            }
            if (resuA[0] > 0)
            {
                flags = flags + "A "; 
            }
            else
            {
                flags = flags + "- "; 
            }
            if (resuP[0] > 0)
            {
                flags = flags + "P ";
            }
            else
            {
                flags = flags + "- ";
            }
            if (resuR[0] > 0)
            {
                flags = flags + "R ";
            }
            else
            {
                flags = flags + "- ";
            }
            if (resuS[0] > 0)
            {
                flags = flags + "S ";
            }
            else
            {
                flags = flags + "- ";
            }
            if (resuF[0] > 0)
            {
                flags = flags + "F ";
            }
            else
            {
                flags = flags + "- ";
            }
            return flags;
        }

        //******************************************************************************************************************************//
        // Program::ToVersionString()
        //******************************************************************************************************************************//
        public static string ToVersionString(this byte b)
        {
            int[] lversion = new int[1] { b >> 4};
            BitArray lBit = new BitArray(lversion);
            //PrintBits(lBit);

            int[] lmask = new int[1] { 15 };
            BitArray lBit15 = new BitArray(lmask);

            int[] resu = new int[1];
            lBit.And(lBit15).CopyTo(resu,0);
            //Console.WriteLine("{0}", resu[0].ToString());

            switch (resu[0])
            {
                case 4: return "4";
                case 6: return "6";
                default: return "#" + resu[0].ToString();
            }
        }

        //******************************************************************************************************************************//
        // Program::ToIHLString()
        //******************************************************************************************************************************//
        public static string ToIHLString(this byte b)
        {
            int[] lversion = new int[1] { b };
            BitArray lBit = new BitArray(lversion);
            //PrintBits(lBit);

            int[] lmask = new int[1] { 15 };
            BitArray lBit15 = new BitArray(lmask);

            int[] resu = new int[1];
            lBit.And(lBit15).CopyTo(resu, 0);
            //Console.WriteLine("{0}", resu[0].ToString());

            return (resu[0] * 4).ToString();
        }

        //******************************************************************************************************************************//
        // Program::ToHLString()
        //******************************************************************************************************************************//
        public static string ToHLString(this byte b)
        {
            int[] lHL = new int[1] { b >> 4 };
            BitArray lBit = new BitArray(lHL);
            //PrintBits(lBit);

            int[] lmask = new int[1] { 15 };
            BitArray lBit15 = new BitArray(lmask);

            int[] resu = new int[1];
            lBit.And(lBit15).CopyTo(resu, 0);
            //Console.WriteLine("{0}", resu[0].ToString());

            return (resu[0] * 4).ToString();
        }

        //******************************************************************************************************************************//
        // Program::ToDiffServString()
        //******************************************************************************************************************************//
        public static string ToDiffServString(this byte b)
        {
            int[] lversion = new int[1] { b >> 2 };
            BitArray lBit = new BitArray(lversion);
            //PrintBits(lBit);

            int[] lmask = new int[1] { 63 };
            BitArray lBit15 = new BitArray(lmask);

            int[] resu = new int[1];
            lBit.And(lBit15).CopyTo(resu, 0);
            //Console.WriteLine("{0}", resu[0].ToString());

            return (resu[0]).ToString();
        }

        //******************************************************************************************************************************//
        // Program::ToECNString()
        //******************************************************************************************************************************//
        public static string ToECNString(this byte b)
        {
            int[] lversion = new int[1] { b };
            BitArray lBit = new BitArray(lversion);
            //PrintBits(lBit);

            int[] lmask = new int[1] { 3 };
            BitArray lBit15 = new BitArray(lmask);

            int[] resu = new int[1];
            lBit.And(lBit15).CopyTo(resu, 0);
            //Console.WriteLine("{0}", resu[0].ToString());

            return (resu[0]).ToString();
        }

        //******************************************************************************************************************************//
        // Program::PrintBits()
        //******************************************************************************************************************************//
        private static void PrintBits(IEnumerable bits)
        {
            int i = 0;
            foreach (bool bit in bits)
            {
                if ((i % 8 == 0) && (i != 0))
                    Console.Write("  ");
         
                Console.Write("{0,2}", ((bit == true) ? "T" : "F"));
         
                i++;
         
                if (i > 31)
                {
                    i = 0;
                    Console.WriteLine();
                }
            }
            Console.WriteLine();
        }
    }

    //******************************************************************************************************************************//
    //******************************************************************************************************************************//
    // class StateObject
    //    State object for reading client data asynchronously
    //******************************************************************************************************************************//
    //******************************************************************************************************************************//
    public class StateObject
    {
        // Client  socket.
        public Socket workSocket = null;
        // Size of receive buffer.
        public const int BufferSize = 1024;
        // Receive buffer.
        public byte[] buffer = new byte[BufferSize];
        // Received data string.
        public StringBuilder sb = new StringBuilder();
    }

    //******************************************************************************************************************************//
    //******************************************************************************************************************************//
    // class handleClinet
    //******************************************************************************************************************************//
    //******************************************************************************************************************************//
    public class handleClinet
    {
        TcpClient clientSocket;
        string clNo;
        Semaphore l_SEM_client_authenticated = new Semaphore(initialCount: 3, maximumCount: 3, name: "PrinterApp");

        // client message
        const String DEF_INPUT = "0", DEF_PING = "1", DEF_RESIZE_TERMINAL = "2", DEF_JSON_DATA = "{";

        // server message
        const String DEF_CRLF = "\n\r", DEF_OUTPUT = "0", DEF_PONG = "1", DEF_SET_WINDOW_TITLE = "2", DEF_SET_PREFERENCES = "3", DEF_SET_RECONNECT = "4";


        //******************************************************************************************************************************//
        // handleClinet::GetAllFootprints()
        //******************************************************************************************************************************//
        private string GetAllFootprints(Exception x)
        {
            var st = new StackTrace(x, true);
            var frames = st.GetFrames();
            var traceString = new StringBuilder();

            foreach (var frame in frames)
            {
                if (frame.GetFileLineNumber() < 1)
                    continue;

                traceString.Append("File: " + frame.GetFileName());
                traceString.Append(", Method:" + frame.GetMethod().Name);
                traceString.Append(", LineNumber: " + frame.GetFileLineNumber());
                traceString.Append("  -->  ");
            }

            return traceString.ToString();
        }

        //******************************************************************************************************************************//
        // handleClinet::T[]()
        //******************************************************************************************************************************//
        public static T[] SubArray<T>(T[] data, int index, int length)
        {
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }


        //******************************************************************************************************************************//
        // handleClinet::EncodeMessageToSend()
        //******************************************************************************************************************************//
        private static Byte[] EncodeMessageToSend(string message)
        {
            /* this is how and header should be made:
             *   - first byte  -> FIN + RSV1 + RSV2 + RSV3 + OPCODE
             *   - second byte -> MASK + payload length (only 7 bits)
             *   - third, fourth, fifth and sixth bytes -> (optional) XOR encoding key bytes
             *   - following bytes -> the encoded (if a key has been used) payload
             *
             *   FIN    [1 bit]      -> 1 if the whole message is contained in this frame, 0 otherwise
             *   RSVs   [1 bit each] -> MUST be 0 unless an extension is negotiated that defines meanings for non-zero values
             *   OPCODE [4 bits]     -> defines the interpretation of the carried payload
             *
             *   MASK           [1 bit]  -> 1 if the message is XOR masked with a key, 0 otherwise
             *   payload length [7 bits] -> can be max 1111111 (127 dec), so, the payload cannot be more than 127 bytes per frame
             *
             * valid OPCODES:
             *   - 0000 [0]             -> continuation frame
             *   - 0001 [1]             -> text frame
             *   - 0010 [2]             -> binary frame
             *   - 0011 [3] to 0111 [7] -> reserved for further non-control frames
             *   - 1000 [8]             -> connection close
             *   - 1001 [9]             -> ping
             *   - 1010 [A]             -> pong
             *   - 1011 [B] to 1111 [F] -> reserved for further control frames
             */
            // in our case the first byte will be 10000020 (130 dec = 82 hex).
            // the length is going to be (masked)1 << 7 (OR) 0 + payload length.
            Byte[] response;
            Byte[] bytesRaw = Encoding.UTF8.GetBytes(message);
            Byte[] frame = new Byte[10];

            Int32 indexStartRawData = -1;
            Int32 length = bytesRaw.Length;

            frame[0] = (Byte)0x82;
            if (length <= 125)
            {
                frame[1] = (Byte)length;
                indexStartRawData = 2;
            }
            else if (length >= 126 && length <= 65535)
            {
                frame[1] = (Byte)126;
                frame[2] = (Byte)((length >> 8) & 255);
                frame[3] = (Byte)(length & 255);
                indexStartRawData = 4;
            }
            else
            {
                frame[1] = (Byte)127;
                frame[2] = (Byte)((length >> 56) & 255);
                frame[3] = (Byte)((length >> 48) & 255);
                frame[4] = (Byte)((length >> 40) & 255);
                frame[5] = (Byte)((length >> 32) & 255);
                frame[6] = (Byte)((length >> 24) & 255);
                frame[7] = (Byte)((length >> 16) & 255);
                frame[8] = (Byte)((length >> 8) & 255);
                frame[9] = (Byte)(length & 255);

                indexStartRawData = 10;
            }

            response = new Byte[indexStartRawData + length];

            Int32 i, reponseIdx = 0;

            //Add the frame bytes to the reponse
            for (i = 0; i < indexStartRawData; i++)
            {
                response[reponseIdx] = frame[i];
                reponseIdx++;
            }

            //Add the data bytes to the response
            for (i = 0; i < length; i++)
            {
                response[reponseIdx] = bytesRaw[i];
                reponseIdx++;
            }

            return response;
        }

        //******************************************************************************************************************************//
        // handleClinet::SendTcp()
        //******************************************************************************************************************************//
        static public int SendTcp(NetworkStream stream, string aTCP)
        {
            try
            {
                Byte[] encoded = EncodeMessageToSend(DEF_OUTPUT + aTCP + DEF_CRLF);
                
                stream.Write(encoded, 0, encoded.Length);
                stream.Flush();
                return 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine(">> EXCEPTION SendTcp({0}) : " + ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
                return 0;
            }
        }

        //******************************************************************************************************************************//
        // handleClinet::SslSendTcp()
        //******************************************************************************************************************************//
        static public int SslSendTcp(SslStream stream, string aTCP)
        {
            Byte[] encoded = EncodeMessageToSend(DEF_OUTPUT + aTCP + DEF_CRLF);
            try
            {
                //stream.Write(encoded, 0, encoded.Length);
                stream.Write(encoded);
                stream.Flush();
                return 1;
            }
            catch (NotSupportedException ex)
            {
                Console.WriteLine("EXCEPTION: NotSupportedException stream.Write ({0}): " + ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
                return 0;
            }
            catch (ObjectDisposedException ex)
            {
                Console.WriteLine("EXCEPTION: ObjectDisposedException stream.Write ({0}): " + ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
                return 0;
            }
            catch (IOException ex)
            {
                Console.WriteLine("EXCEPTION: IOException stream.Write ({0}): " + ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
                return 0;
            }
        }

        //******************************************************************************************************************************//
        // handleClinet::SnifferSync()
        //******************************************************************************************************************************//
        public static void SnifferSync(NetworkStream stream)
        {
            // we are only listening to IPv4 interfaces
            var IPv4Addresses = Dns.GetHostEntry(Dns.GetHostName())
                .AddressList.Where(al => al.AddressFamily == AddressFamily.InterNetwork)
                .AsEnumerable();

            foreach (IPAddress ip in IPv4Addresses)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    //System.Diagnostics.Debug.WriteLine("LocalIPadress: " + ip);
                    Console.WriteLine("INFO: LocalIPaddress : " + ip.ToString());
                }
            }

            Socket sck = null;

            try
            {
                // setup the socket to listen on, we are listening just to IPv4 IPAddresses
                sck = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

                sck.Bind(new IPEndPoint(IPv4Addresses.Last(), 0));

                sck.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                byte[] byTrue = new byte[4] { 1, 1, 0, 0 };
                byte[] byOut = new byte[4] { 1, 1, 0, 0 };

                sck.IOControl(ioControlCode: IOControlCode.ReceiveAll, byTrue, byOut);
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: Socket ({0}): please check that the tool is launched by a user with admin rights !!!" + ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
                return;
            }

            while (true)
            {
                byte[] buffer = new byte[sck.ReceiveBufferSize];

                int count = sck.Receive(buffer);
                //int byteRead = sck.EndReceive(ar);

                string IPsource = new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString();
                string IPtarget = new IPAddress(BitConverter.ToUInt32(buffer, 16)).ToString();

                //"(ip)", "and", "(not", "(broadcast", "or", "multicast)", "and", "not", "(port", "514)", "and", "not", "(src", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4)", "and", "dst", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4))                    
                bool IgnoreLocalPacket = new System.Text.RegularExpressions.Regex("127.*").Match(IPsource).Success;
                //IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex("10.*").Match(IPsource).Success;
                IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex("169.254.*").Match(IPsource).Success;
                IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex("224.*").Match(IPsource).Success;
                IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex("54.224.*").Match(IPsource).Success;
                if (Program.IPSvrBeeWoo != null)
                {
                    IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrBeeWoo).Match(IPtarget).Success;
                    IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrBeeWoo).Match(IPsource).Success;
                }
                if (Program.IPSvrLambdaLocalization != null)
                {
                    IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrLambdaLocalization).Match(IPtarget).Success;
                    IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrLambdaLocalization).Match(IPsource).Success;
                }
                if (Program.IPSvrKinesisFirehose != null)
                {
                    IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrKinesisFirehose).Match(IPtarget).Success;
                    IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrKinesisFirehose).Match(IPsource).Success;
                }
                
                if (IgnoreLocalPacket)
                {
                }
                else
                {
                    ushort aFlag = (ushort)BitConverter.ToInt16(buffer, 32);
                    byte aProtocol = buffer.Skip(9).First();
                    string to_send = "";

                    // TCP
                    if (aProtocol == 6)
                    {
                        //All of the data has been read, so displays it to the console
                        to_send = String.Format("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13} {14} {15} {16} {17} {18} {19} {20}"
                        , DateTimeOffset.Now.ToUnixTimeSeconds()                                                // 0 : TimeStamp
                        , buffer.First().ToVersionString()                                                      // 1 : [0] / IP Version
                        , buffer.First().ToIHLString()                                                          // 2 : [0] / IHL IP Header Length
                        , buffer.Skip(1).First().ToDiffServString()                                             // 3 : [1] / Type Of Service Diffserv
                        , ((ushort)BitConverter.ToUInt16(buffer, 2)).ToString()                                  // 4 : [2-3] / Length
                        , ((ushort)BitConverter.ToUInt16(buffer, 4)).ToString()                                  // 5 : [4-5] / Identification
                        , ((ushort)BitConverter.ToUInt16(buffer, 6)).ToString()                                  // 6 : [6-7] / Offset
                        , buffer.Skip(8).First().ToString()                                                     // 7 : [8] / TTL
                        , aProtocol.ToString()                                                                  // 8 : [9] / Protocol
                        , ((ushort)BitConverter.ToUInt16(buffer, 10)).ToString()                                 // 9 : [10-11] / Check Sum
                        , IPsource                                                                              // 10: [12-15] / IP source
                        , IPtarget                                                                              // 11: [16-19] / IP destination
                        , ((ushort)BitConverter.ToUInt16(buffer, 20)).ToString()                                // 12: [20-21] / port source
                        , ((ushort)BitConverter.ToUInt16(buffer, 22)).ToString()                                // 13: [22-23] / port destination
                        , ((uint)BitConverter.ToInt32(buffer, 24)).ToString()                                  // 14: [24-27] / Sequence Number
                        , ((uint)BitConverter.ToInt32(buffer, 28)).ToString()                                  // 15: [28-31] / Acknowledge Number
                        , buffer.Skip(32).First().ToHLString()                                                  // 16: [32] / Header Length
                        , ((ushort)BitConverter.ToUInt16(buffer, 32)).ToFlagString()                             // 17: [33] / Flags
                        , ((ushort)BitConverter.ToUInt16(buffer, 34)).ToString()                                 // 18: [34-35] / Window 
                        , ((ushort)BitConverter.ToUInt16(buffer, 36)).ToString()                                 // 19: [36-37] / Checksum 
                        , ((ushort)BitConverter.ToUInt16(buffer, 38)).ToString());                               // 20: [38-39] / Urgent Ptr 
                    }
                    // UDP
                    else if (aProtocol == 17)
                    {
                        //All of the data has been read, so displays it to the console
                        to_send = String.Format("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13} {14} {15} {16} {17} {18} {19} {20}"
                        , DateTimeOffset.Now.ToUnixTimeSeconds()                                                // 0 : TimeStamp
                        , buffer.First().ToVersionString()                                                      // 1 : [0] / IP Version
                        , buffer.First().ToIHLString()                                                          // 2 : [0] / IHL IP Header Length
                        , buffer.Skip(1).First().ToDiffServString()                                             // 3 : [1] / Type Of Service Diffserv
                        , ((ushort)BitConverter.ToUInt16(buffer, 2)).ToString()                                  // 4 : [2-3] / Length
                        , ((ushort)BitConverter.ToUInt16(buffer, 4)).ToString()                                  // 5 : [4-5] / Identification
                        , ((ushort)BitConverter.ToUInt16(buffer, 6)).ToString()                                  // 6 : [6-7] / Offset
                        , buffer.Skip(8).First().ToString()                                                     // 7 : [8] / TTL
                        , aProtocol.ToString()                                                                  // 8 : [9] / Protocol
                        , ((ushort)BitConverter.ToUInt16(buffer, 10)).ToString()                                 // 9 : [10-11] / Check Sum
                        , IPsource                                                                              // 10: [12-15] / IP source
                        , IPtarget                                                                              // 11: [16-19] / IP destination
                        , ((ushort)BitConverter.ToUInt16(buffer, 20)).ToString()                                // 12: [20-21] / port source
                        , ((ushort)BitConverter.ToUInt16(buffer, 22)).ToString()                                // 13: [22-23] / port destination
                        , ((uint)BitConverter.ToInt32(buffer, 24)).ToString()                                  // 14: [24-27] / Sequence Number
                        , ((uint)BitConverter.ToInt32(buffer, 28)).ToString()                                  // 15: [28-31] / Acknowledge Number
                        , buffer.Skip(32).First().ToHLString()                                                  // 16: [32] / Header Length
                        , "- - - - - -"                             // 17: [33] / Flags
                        , "0"                                 // 18: [34-35] / Window 
                        , "0"                                 // 19: [36-37] / Checksum 
                        , "0");                               // 20: [38-39] / Urgent Ptr 
                    }
                    // IGMP
                    else if (aProtocol == 2)
                    {
                        //All of the data has been read, so displays it to the console
                        to_send = String.Format("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13} {14} {15} {16} {17} {18} {19} {20}"
                        , DateTimeOffset.Now.ToUnixTimeSeconds()                                                // 0 : TimeStamp
                        , buffer.First().ToVersionString()                                                      // 1 : [0] / IP Version
                        , buffer.First().ToIHLString()                                                          // 2 : [0] / IHL IP Header Length
                        , buffer.Skip(1).First().ToDiffServString()                                             // 3 : [1] / Type Of Service Diffserv
                        , ((ushort)BitConverter.ToUInt16(buffer, 2)).ToString()                                  // 4 : [2-3] / Length
                        , ((ushort)BitConverter.ToUInt16(buffer, 4)).ToString()                                  // 5 : [4-5] / Identification
                        , ((ushort)BitConverter.ToUInt16(buffer, 6)).ToString()                                  // 6 : [6-7] / Offset
                        , buffer.Skip(8).First().ToString()                                                     // 7 : [8] / TTL
                        , aProtocol.ToString()                                                                  // 8 : [9] / Protocol
                        , ((ushort)BitConverter.ToUInt16(buffer, 10)).ToString()                                 // 9 : [10-11] / Check Sum
                        , IPsource                                                                              // 10: [12-15] / IP source
                        , IPtarget                                                                              // 11: [16-19] / IP destination
                        , ((ushort)BitConverter.ToUInt16(buffer, 20)).ToString()                                // 12: [20-21] / port source
                        , ((ushort)BitConverter.ToUInt16(buffer, 22)).ToString()                                // 13: [22-23] / port destination
                        , ((uint)BitConverter.ToInt32(buffer, 24)).ToString()                                  // 14: [24-27] / Sequence Number
                        , ((uint)BitConverter.ToInt32(buffer, 28)).ToString()                                  // 15: [28-31] / Acknowledge Number
                        , buffer.Skip(32).First().ToHLString()                                                  // 16: [32] / Header Length
                        , "- - - - - -"                             // 17: [33] / Flags
                        , "0"                                 // 18: [34-35] / Window 
                        , "0"                                 // 19: [36-37] / Checksum 
                        , "0");                               // 20: [38-39] / Urgent Ptr 
                    }
                    // ICMP
                    else if (aProtocol == 1)
                    {
                        //All of the data has been read, so displays it to the console
                        to_send = String.Format("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13} {14} {15} {16} {17} {18} {19} {20}"
                        , DateTimeOffset.Now.ToUnixTimeSeconds()                                                // 0 : TimeStamp
                        , buffer.First().ToVersionString()                                                      // 1 : [0] / IP Version
                        , buffer.First().ToIHLString()                                                          // 2 : [0] / IHL IP Header Length
                        , buffer.Skip(1).First().ToDiffServString()                                             // 3 : [1] / Type Of Service Diffserv
                        , ((ushort)BitConverter.ToUInt16(buffer, 2)).ToString()                                  // 4 : [2-3] / Length
                        , ((ushort)BitConverter.ToUInt16(buffer, 4)).ToString()                                  // 5 : [4-5] / Identification
                        , ((ushort)BitConverter.ToUInt16(buffer, 6)).ToString()                                  // 6 : [6-7] / Offset
                        , buffer.Skip(8).First().ToString()                                                     // 7 : [8] / TTL
                        , aProtocol.ToString()                                                                  // 8 : [9] / Protocol
                        , ((ushort)BitConverter.ToUInt16(buffer, 10)).ToString()                                 // 9 : [10-11] / Check Sum
                        , IPsource                                                                              // 10: [12-15] / IP source
                        , IPtarget                                                                              // 11: [16-19] / IP destination
                        , ((ushort)BitConverter.ToUInt16(buffer, 20)).ToString()                                // 12: [20-21] / port source
                        , ((ushort)BitConverter.ToUInt16(buffer, 22)).ToString()                                // 13: [22-23] / port destination
                        , ((uint)BitConverter.ToInt32(buffer, 24)).ToString()                                  // 14: [24-27] / Sequence Number
                        , ((uint)BitConverter.ToInt32(buffer, 28)).ToString()                                  // 15: [28-31] / Acknowledge Number
                        , buffer.Skip(32).First().ToHLString()                                                  // 16: [32] / Header Length
                        , "- - - - - -"                             // 17: [33] / Flags
                        , "0"                                 // 18: [34-35] / Window 
                        , "0"                                 // 19: [36-37] / Checksum 
                        , "0");                               // 20: [38-39] / Urgent Ptr 
                    }

                    Console.WriteLine(String.Format("{0}", to_send));
                    if (SendTcp(stream, to_send) == 0) break;

                }
            }
        }

        //******************************************************************************************************************************//
        // handleClinet::SslSnifferSync()
        //******************************************************************************************************************************//
        public static int SslSnifferSync(SslStream stream)
        {
            // we are only listening to IPv4 interfaces
            var IPv4Addresses = Dns.GetHostEntry(Dns.GetHostName())
                .AddressList.Where(al => al.AddressFamily == AddressFamily.InterNetwork)
                .AsEnumerable();
            Socket sck = null;

            int i = 0;
            foreach (IPAddress ip in IPv4Addresses)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    //System.Diagnostics.Debug.WriteLine("LocalIPadress: " + ip);
                    Console.WriteLine("> " + i.ToString() + " = " + ip.ToString());
                    i++;
                }
            }
            Console.Write("> Entrez le numéro de l'interface à sniffer: ");
            string myChoiceStr = Console.ReadLine();
            int theIndex = Convert.ToInt32(myChoiceStr);

            try
            { 
                // setup the socket to listen on, we are listening just to IPv4 IPAddresses
                sck = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

                sck.Bind(new IPEndPoint(IPv4Addresses.ElementAt(theIndex), 0));

                sck.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                byte[] byTrue = new byte[4] { 1, 1, 0, 0 };
                byte[] byOut = new byte[4] { 1, 1, 0, 0 };
                sck.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);

                while (true)
                {
                    byte[] buffer = new byte[sck.ReceiveBufferSize];

                    int count = sck.Receive(buffer);
                    //int byteRead = sck.EndReceive(ar);

                    string IPsource = new IPAddress(BitConverter.ToUInt32(buffer, 12)).ToString();
                    string IPtarget = new IPAddress(BitConverter.ToUInt32(buffer, 16)).ToString();

                    //"(ip)", "and", "(not", "(broadcast", "or", "multicast)", "and", "not", "(port", "514)", "and", "not", "(src", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4)", "and", "dst", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4))                    
                    bool IgnoreLocalPacket = new System.Text.RegularExpressions.Regex("127.*").Match(IPsource).Success;
                    //IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex("10.*").Match(IPsource).Success;
                    IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex("169.254.*").Match(IPsource).Success;
                    IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex("224.*").Match(IPsource).Success;
                    if (Program.IPSvrBeeWoo != null)
                    {
                        IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrBeeWoo).Match(IPtarget).Success;
                        IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrBeeWoo).Match(IPsource).Success;
                    }
                    if (Program.IPSvrKinesisFirehose != null)
                    {
                        IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrKinesisFirehose).Match(IPtarget).Success;
                        IgnoreLocalPacket |= new System.Text.RegularExpressions.Regex(Program.IPSvrKinesisFirehose).Match(IPsource).Success;
                    }
                    if (IgnoreLocalPacket)
                    {
                    }
                    else
                    {
                        ushort aFlag = (ushort)BitConverter.ToInt16(buffer, 32);
                        byte aProtocol = buffer.Skip(9).First();
                        string to_send = "";

                        // TCP
                        if (aProtocol == 6)
                        {
                            //All of the data has been read, so displays it to the console
                            to_send = String.Format("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13} {14} {15} {16} {17} {18} {19} {20}"
                            , DateTimeOffset.Now.ToUnixTimeSeconds()                                                // 0 : TimeStamp
                            , buffer.First().ToVersionString()                                                      // 1 : [0] / IP Version
                            , buffer.First().ToIHLString()                                                          // 2 : [0] / IHL IP Header Length
                            , buffer.Skip(1).First().ToDiffServString()                                             // 3 : [1] / Type Of Service Diffserv
                            , ((ushort)BitConverter.ToUInt16(buffer, 2)).ToString()                                  // 4 : [2-3] / Length
                            , ((ushort)BitConverter.ToUInt16(buffer, 4)).ToString()                                  // 5 : [4-5] / Identification
                            , ((ushort)BitConverter.ToUInt16(buffer, 6)).ToString()                                  // 6 : [6-7] / Offset
                            , buffer.Skip(8).First().ToString()                                                     // 7 : [8] / TTL
                            , aProtocol.ToString()                                                                  // 8 : [9] / Protocol
                            , ((ushort)BitConverter.ToUInt16(buffer, 10)).ToString()                                 // 9 : [10-11] / Check Sum
                            , IPsource                                                                              // 10: [12-15] / IP source
                            , IPtarget                                                                              // 11: [16-19] / IP destination
                            , ((ushort)BitConverter.ToUInt16(buffer, 20)).ToString()                                // 12: [20-21] / port source
                            , ((ushort)BitConverter.ToUInt16(buffer, 22)).ToString()                                // 13: [22-23] / port destination
                            , ((uint)BitConverter.ToInt32(buffer, 24)).ToString()                                  // 14: [24-27] / Sequence Number
                            , ((uint)BitConverter.ToInt32(buffer, 28)).ToString()                                  // 15: [28-31] / Acknowledge Number
                            , buffer.Skip(32).First().ToHLString()                                                  // 16: [32] / Header Length
                            , ((ushort)BitConverter.ToUInt16(buffer, 32)).ToFlagString()                             // 17: [33] / Flags
                            , ((ushort)BitConverter.ToUInt16(buffer, 34)).ToString()                                 // 18: [34-35] / Window 
                            , ((ushort)BitConverter.ToUInt16(buffer, 36)).ToString()                                 // 19: [36-37] / Checksum 
                            , ((ushort)BitConverter.ToUInt16(buffer, 38)).ToString());                               // 20: [38-39] / Urgent Ptr 
                        }
                        // UDP
                        else if (aProtocol == 17)
                        {
                            //All of the data has been read, so displays it to the console
                            to_send = String.Format("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13} {14} {15} {16} {17} {18} {19} {20}"
                            , DateTimeOffset.Now.ToUnixTimeSeconds()                                                // 0 : TimeStamp
                            , buffer.First().ToVersionString()                                                      // 1 : [0] / IP Version
                            , buffer.First().ToIHLString()                                                          // 2 : [0] / IHL IP Header Length
                            , buffer.Skip(1).First().ToDiffServString()                                             // 3 : [1] / Type Of Service Diffserv
                            , ((ushort)BitConverter.ToUInt16(buffer, 2)).ToString()                                  // 4 : [2-3] / Length
                            , ((ushort)BitConverter.ToUInt16(buffer, 4)).ToString()                                  // 5 : [4-5] / Identification
                            , ((ushort)BitConverter.ToUInt16(buffer, 6)).ToString()                                  // 6 : [6-7] / Offset
                            , buffer.Skip(8).First().ToString()                                                     // 7 : [8] / TTL
                            , aProtocol.ToString()                                                                  // 8 : [9] / Protocol
                            , ((ushort)BitConverter.ToUInt16(buffer, 10)).ToString()                                 // 9 : [10-11] / Check Sum
                            , IPsource                                                                              // 10: [12-15] / IP source
                            , IPtarget                                                                              // 11: [16-19] / IP destination
                            , ((ushort)BitConverter.ToUInt16(buffer, 20)).ToString()                                // 12: [20-21] / port source
                            , ((ushort)BitConverter.ToUInt16(buffer, 22)).ToString()                                // 13: [22-23] / port destination
                            , ((uint)BitConverter.ToInt32(buffer, 24)).ToString()                                  // 14: [24-27] / Sequence Number
                            , ((uint)BitConverter.ToInt32(buffer, 28)).ToString()                                  // 15: [28-31] / Acknowledge Number
                            , buffer.Skip(32).First().ToHLString()                                                  // 16: [32] / Header Length
                            , "- - - - - -"                             // 17: [33] / Flags
                            , "0"                                 // 18: [34-35] / Window 
                            , "0"                                 // 19: [36-37] / Checksum 
                            , "0");                               // 20: [38-39] / Urgent Ptr 
                        }
                        // IGMP
                        else if (aProtocol == 2)
                        {
                            //All of the data has been read, so displays it to the console
                            to_send = String.Format("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13} {14} {15} {16} {17} {18} {19} {20}"
                            , DateTimeOffset.Now.ToUnixTimeSeconds()                                                // 0 : TimeStamp
                            , buffer.First().ToVersionString()                                                      // 1 : [0] / IP Version
                            , buffer.First().ToIHLString()                                                          // 2 : [0] / IHL IP Header Length
                            , buffer.Skip(1).First().ToDiffServString()                                             // 3 : [1] / Type Of Service Diffserv
                            , ((ushort)BitConverter.ToUInt16(buffer, 2)).ToString()                                  // 4 : [2-3] / Length
                            , ((ushort)BitConverter.ToUInt16(buffer, 4)).ToString()                                  // 5 : [4-5] / Identification
                            , ((ushort)BitConverter.ToUInt16(buffer, 6)).ToString()                                  // 6 : [6-7] / Offset
                            , buffer.Skip(8).First().ToString()                                                     // 7 : [8] / TTL
                            , aProtocol.ToString()                                                                  // 8 : [9] / Protocol
                            , ((ushort)BitConverter.ToUInt16(buffer, 10)).ToString()                                 // 9 : [10-11] / Check Sum
                            , IPsource                                                                              // 10: [12-15] / IP source
                            , IPtarget                                                                              // 11: [16-19] / IP destination
                            , ((ushort)BitConverter.ToUInt16(buffer, 20)).ToString()                                // 12: [20-21] / port source
                            , ((ushort)BitConverter.ToUInt16(buffer, 22)).ToString()                                // 13: [22-23] / port destination
                            , ((uint)BitConverter.ToInt32(buffer, 24)).ToString()                                  // 14: [24-27] / Sequence Number
                            , ((uint)BitConverter.ToInt32(buffer, 28)).ToString()                                  // 15: [28-31] / Acknowledge Number
                            , buffer.Skip(32).First().ToHLString()                                                  // 16: [32] / Header Length
                            , "- - - - - -"                             // 17: [33] / Flags
                            , "0"                                 // 18: [34-35] / Window 
                            , "0"                                 // 19: [36-37] / Checksum 
                            , "0");                               // 20: [38-39] / Urgent Ptr 
                        }
                        // ICMP
                        else if (aProtocol == 1)
                        {
                            //All of the data has been read, so displays it to the console
                            to_send = String.Format("{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13} {14} {15} {16} {17} {18} {19} {20}"
                            , DateTimeOffset.Now.ToUnixTimeSeconds()                                                // 0 : TimeStamp
                            , buffer.First().ToVersionString()                                                      // 1 : [0] / IP Version
                            , buffer.First().ToIHLString()                                                          // 2 : [0] / IHL IP Header Length
                            , buffer.Skip(1).First().ToDiffServString()                                             // 3 : [1] / Type Of Service Diffserv
                            , ((ushort)BitConverter.ToUInt16(buffer, 2)).ToString()                                  // 4 : [2-3] / Length
                            , ((ushort)BitConverter.ToUInt16(buffer, 4)).ToString()                                  // 5 : [4-5] / Identification
                            , ((ushort)BitConverter.ToUInt16(buffer, 6)).ToString()                                  // 6 : [6-7] / Offset
                            , buffer.Skip(8).First().ToString()                                                     // 7 : [8] / TTL
                            , aProtocol.ToString()                                                                  // 8 : [9] / Protocol
                            , ((ushort)BitConverter.ToUInt16(buffer, 10)).ToString()                                 // 9 : [10-11] / Check Sum
                            , IPsource                                                                              // 10: [12-15] / IP source
                            , IPtarget                                                                              // 11: [16-19] / IP destination
                            , ((ushort)BitConverter.ToUInt16(buffer, 20)).ToString()                                // 12: [20-21] / port source
                            , ((ushort)BitConverter.ToUInt16(buffer, 22)).ToString()                                // 13: [22-23] / port destination
                            , ((uint)BitConverter.ToInt32(buffer, 24)).ToString()                                  // 14: [24-27] / Sequence Number
                            , ((uint)BitConverter.ToInt32(buffer, 28)).ToString()                                  // 15: [28-31] / Acknowledge Number
                            , buffer.Skip(32).First().ToHLString()                                                  // 16: [32] / Header Length
                            , "- - - - - -"                             // 17: [33] / Flags
                            , "0"                                 // 18: [34-35] / Window 
                            , "0"                                 // 19: [36-37] / Checksum 
                            , "0");                               // 20: [38-39] / Urgent Ptr 
                        }

                        Console.WriteLine(String.Format("{0}", to_send));
                        if (SslSendTcp(stream, to_send) == 0) break;

                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("EXCEPTION: ({0}): " + e.Message + "\n\r>>> !!! EXCEPTION Socket :check that you used an admin user ?!!", (int)(new StackTrace(e, true)).GetFrame(0).GetFileLineNumber());
                return -1;
            }
            return 0;
        }


        //******************************************************************************************************************************//
        // handleClinet::Ssl_Serve_index_html()
        //******************************************************************************************************************************//
        private void Ssl_Serve_index_html(SslStream stream)
        {
            try
            {
                //Adding permanent http response headers

                System.IO.StreamWriter writer = new System.IO.StreamWriter(stream);
                writer.Write("HTTP/1.1 200 OK");
                writer.Write(Environment.NewLine);
                writer.Write("Content-Type: text/html; charset=UTF-8");
                writer.Write(Environment.NewLine);
                writer.Write("Content-Length: " + Encoding.ASCII.GetString(oth_html.index_html).Length);
                writer.Write(Environment.NewLine);
                writer.Write(Environment.NewLine);
                writer.Write(Encoding.ASCII.GetString(oth_html.index_html));
                writer.Flush();
                //Console.WriteLine(">> Serve_index_html processed OK");
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: {1} - Serve_index_html {0}", ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
            }
        }


        //******************************************************************************************************************************//
        // handleClinet::Ssl_RespondToAuthentication()
        //******************************************************************************************************************************//
        private void Ssl_RespondToAuthentication(SslStream stream)
        {
            try
            {
                //Adding permanent http response headers

                System.IO.StreamWriter writer = new System.IO.StreamWriter(stream);
                writer.Write("HTTP/1.1 200 OK");
                writer.Write(Environment.NewLine);
                writer.Write("Content-Type:  text/plain; charset=UTF-8");
                writer.Write(Environment.NewLine);
                writer.Write("Content-Length: " + 0);
                writer.Write(Environment.NewLine);
                writer.Write(Environment.NewLine);
                writer.Write("");
                writer.Flush();
                //Console.WriteLine(">> RespondToAuthentication processed OK");

            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: RespondToAuthentication ({0})" + ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
            }
        }

        //******************************************************************************************************************************//
        // handleClinet::RespondToSniffer()
        //******************************************************************************************************************************//
        private void RespondToSniffer(NetworkStream stream, String aGet)
        {
            try
            {
                //Adding permanent http response headers
                const string eol = "\r\n"; // HTTP/1.1 defines the sequence CR LF as the end-of-line marker

                string websock_key = Convert.ToBase64String(
                            System.Security.Cryptography.SHA1.Create().ComputeHash(
                                Encoding.UTF8.GetBytes(
                                    new System.Text.RegularExpressions.Regex("Sec-WebSocket-Key: (.*)").Match(aGet).Groups[1].Value.Trim() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));

                Byte[] response = Encoding.UTF8.GetBytes("HTTP/1.1 101 Switching Protocols" + eol
                        + "Connection: Upgrade" + eol
                        + "Upgrade: websocket" + eol
                        + "Sec-WebSocket-Accept: " + websock_key + eol + eol);

                StreamWriter sw = new StreamWriter(stream, Encoding.UTF8);
                sw.WriteLine("HTTP/1.1 101 Switching Protocols");
                sw.WriteLine("Upgrade: websocket");
                sw.WriteLine("Connection: Upgrade");
                sw.WriteLine("Sec-WebSocket-Accept: " + websock_key);
                sw.WriteLine("Sec-WebSocket-Protocol: tty");
                sw.WriteLine("");
                sw.Flush();

                //Console.WriteLine(">> RespondToSniffer Upgrade: websocket SENT to client");

            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: {1} - RespondToSniffer {0}" + ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
            }
        }

        //******************************************************************************************************************************//
        // handleClinet::Ssl_RespondToBrowserWebSocketUpgrade()
        //******************************************************************************************************************************//
        private void Ssl_RespondToBrowserWebSocketUpgrade(SslStream stream, String aGet)
        {
            try
            {
                //Adding permanent http response headers
                const string eol = "\r\n"; // HTTP/1.1 defines the sequence CR LF as the end-of-line marker

                string websock_key = Convert.ToBase64String(
                            System.Security.Cryptography.SHA1.Create().ComputeHash(
                                Encoding.UTF8.GetBytes(
                                    new System.Text.RegularExpressions.Regex("Sec-WebSocket-Key: (.*)").Match(aGet).Groups[1].Value.Trim() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));

                Byte[] response = Encoding.UTF8.GetBytes("HTTP/1.1 101 Switching Protocols" + eol
                        + "Connection: Upgrade" + eol
                        + "Upgrade: websocket" + eol
                        + "Sec-WebSocket-Accept: " + websock_key + eol + eol);

                StreamWriter sw = new StreamWriter(stream, Encoding.UTF8);
                sw.WriteLine("HTTP/1.1 Switching Protocols");
                sw.WriteLine("Upgrade: websocket");
                sw.WriteLine("Connection: Upgrade");
                sw.WriteLine("Sec-WebSocket-Accept: " + websock_key);
                sw.WriteLine("Sec-WebSocket-Protocol: tty");
                sw.WriteLine("");
                sw.Flush();

                //Console.WriteLine("INFO: RespondToSniffer Upgrade requested by webbrowser client : {0}", response.ToString());

            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: {0} - RespondToSniffer {1}", ex.Message, (int)(new StackTrace(ex, true)).GetFrame(0).GetFileLineNumber());
            }
        }

        //******************************************************************************************************************************//
        // handleClinet::DoProcessGetSsl()
        //******************************************************************************************************************************//
        public int DoProcessGetSsl(SslStream stream, String aGet, String RemoteEndPoint)
        {
            //Console.WriteLine("DEBUG: a browser is connected using HTTPS/TLS from client n°{0} !!!", clNo);
            //Console.WriteLine("DEBUG: Received a Ssl request: <'{0}'>", whatToGet);

            if (aGet.Equals("/"))
            {
                Ssl_Serve_index_html(stream);
            }
            else
            if (aGet.Equals("/auth_token.js"))
            {
                Ssl_RespondToAuthentication(stream);
                DisplayCertificateInformation(stream);
            }
            else
            if (aGet.Equals("/sniffer"))
            {
                //DisplaySecurityLevel(stream);
                //DisplaySecurityServices(stream);
                //DisplayStreamProperties(stream);

                //while (!IsAuthenticated()) Thread.Sleep(1000) ;
                Ssl_RespondToBrowserWebSocketUpgrade(stream, aGet);

                //enter to an infinite cycle to be able to handle every change in stream
                return SslSnifferSync(stream);

            }
            return 0;
        }


        //******************************************************************************************************************************//
        // handleClinet::DisplaySecurityLevel()
        //******************************************************************************************************************************//
        static void DisplaySecurityLevel(SslStream stream)
        {
            Console.WriteLine("DEBUG: Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
            Console.WriteLine("DEBUG: Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
            Console.WriteLine("DEBUG: Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
            Console.WriteLine("DEBUG: Protocol: {0}", stream.SslProtocol);
        }

        //******************************************************************************************************************************//
        // handleClinet::DisplaySecurityServices()
        //******************************************************************************************************************************//
        static void DisplaySecurityServices(SslStream stream)
        {
            Console.WriteLine("DEBUG: Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
            Console.WriteLine("DEBUG: IsSigned: {0}", stream.IsSigned);
            Console.WriteLine("DEBUG: Is Encrypted: {0}", stream.IsEncrypted);
        }

        //******************************************************************************************************************************//
        // handleClinet::DisplayStreamProperties()
        //******************************************************************************************************************************//
        static void DisplayStreamProperties(SslStream stream)
        {
            Console.WriteLine("DEBUG: Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
            Console.WriteLine("DEBUG: Can timeout: {0}", stream.CanTimeout);
        }

        //******************************************************************************************************************************//
        // handleClinet::DisplayCertificateInformation()
        //******************************************************************************************************************************//
        static void DisplayCertificateInformation(SslStream stream)
        {
            //Console.WriteLine("DEBUG: Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Console.WriteLine("DEBUG: local certificate created by {0} & validity from {1} till {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("DEBUG: Certificat local est null.");
            }
            // Display the properties of the client's certificate.
            //X509Certificate remoteCertificate = stream.RemoteCertificate;
            //if (stream.RemoteCertificate != null)
            //{
            //    Console.WriteLine("DEBUG: Remote cert was issued to {0} and is valid from {1} until {2}.",
            //        remoteCertificate.Subject,
            //        remoteCertificate.GetEffectiveDateString(),
            //        remoteCertificate.GetExpirationDateString());
            //}
            //else
            //{
            //    Console.WriteLine("DEBUG: Remote certificate is null.");
            //}
        }

        //******************************************************************************************************************************//
        // handleClinet::ReadMessage()
        //******************************************************************************************************************************//
        private int ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the server.
            // The end of the message is signaled using the
            // "<EOF>" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                try
                {
                    bytes = sslStream.Read(buffer, 0, buffer.Length);

                    if (bytes>0)
                    {
                        // Use Decoder class to convert from bytes to UTF8
                        // in case a character spans two buffers.
                        Decoder decoder = Encoding.UTF8.GetDecoder();
                        char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                        decoder.GetChars(buffer, 0, bytes, chars, 0);
                        messageData.Append(chars);
                        // Check for EOF
                        var whatToGet = new System.Text.RegularExpressions.Regex("^GET (.*) HTTP(.*)").Match(messageData.ToString()).Groups[1].Value.Trim();
                        if (messageData.ToString().Contains("GET /"))
                        {
                            int returnCode = DoProcessGetSsl(sslStream, whatToGet, clientSocket.Client.RemoteEndPoint.ToString());
                            Console.WriteLine("DEBUG: returnCode {0} for DoProcessGetSsl.", returnCode);
                            //if (returnCode == 0) break;
                        }
                    }
                }
                catch (IOException e)
                {
                    Console.WriteLine("EXCEPTION: IOException {1} - sslStream.Read {0}", e.Message, (int)(new StackTrace(e, true)).GetFrame(0).GetFileLineNumber());
                }
                catch (ObjectDisposedException e)
                {
                    Console.WriteLine("EXCEPTION: ObjectDisposedException {1} - sslStream.Read {0}", e.Message, (int)(new StackTrace(e, true)).GetFrame(0).GetFileLineNumber());
                }
                catch (InvalidOperationException e)
                {
                    Console.WriteLine("EXCEPTION: InvalidOperationException {1} - sslStream.Read {0}", e.Message, (int)(new StackTrace(e, true)).GetFrame(0).GetFileLineNumber());
                }
            } while (bytes != 0);

            return 0;
        }

        //******************************************************************************************************************************//
        // handleClinet::DoLoop()
        //******************************************************************************************************************************//
        private void DoLoop()
        {
            byte[] bytesFrom = new byte[32000];

            // SSL enabled by default
            // Non SSL generate error mixed content and web browser parameters must be changed to force mixed content
            if (Program.SSL_ENABLED)
            {
                SslStream stream = new SslStream(clientSocket.GetStream(), false);

                try
                {
                    //stream.AuthenticateAsServer(Program.serverCertificate, false, SslProtocols.Tls12, false);
                    stream.AuthenticateAsServer(Program.serverCertificate);
                    Console.WriteLine("INFO: YEAH !!! AuthenticateAsServer successful from client {0}", clientSocket.Client.RemoteEndPoint);
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine("EXCEPTION: AuthenticateAsServer   {0}", e.Message);
                    Console.WriteLine("         : AuthenticateAsServer : {0}", GetAllFootprints(e));
                    if (e.InnerException != null)
                    {
                        Console.WriteLine("         : AuthenticateAsServer Inner exception: {0}", e.InnerException.Message);
                    }
                    Console.WriteLine("         : closing the connection.");
                    //clientSocket.Client.Close();
                    return;
                }
                catch (Exception e)
                {
                    Console.WriteLine("EXCEPTION: AuthenticateAsServer   {0}", e.Message);
                    Console.WriteLine("         : AuthenticateAsServer : {0}", GetAllFootprints(e));
                    //clientSocket.Client.Close();
                    //return;
                }

                //int bytes_read = 0;

                if(stream.IsAuthenticated)
                {
                    int serverMessage = this.ReadMessage(stream);
                    //int bytes_read = serverMessage.Length;
                }
            }
        }

        //******************************************************************************************************************************//
        // handleClinet::StartClient()
        //******************************************************************************************************************************//
        public void StartClient(TcpClient inClientSocket, string clineNo, string RemoteIP)
        {
            //Program.allDone.Set();
            this.clientSocket = inClientSocket;
            this.clNo = clineNo;

            Thread ctThread = new Thread(DoLoop);
            ctThread.Name = RemoteIP;
            ctThread.Start();
        }
    }
}