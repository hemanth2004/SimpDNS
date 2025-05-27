namespace HMNT.SimpDNS
{
    public class Cli
    {
        private static readonly string prompt = "> ";

        public static int Verbosity = 1;

        public static void Log(string message, int verb = 1)
        {
            if (verb > Verbosity) { return; }
            Console.WriteLine(message);
            Console.Write(prompt);
        }

        public static void LogError(string message, int verb = 1)
        {
            if (verb > Verbosity) { return; }
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message);
            Console.ResetColor();
            Console.Write(prompt);
        }

        public static void HandleCommand(string command, Config config)
        {
            string[] args = command.Split(' ');
            switch (args[0])
            {
                case "local":

                    break;
            }
        }
    }
}
