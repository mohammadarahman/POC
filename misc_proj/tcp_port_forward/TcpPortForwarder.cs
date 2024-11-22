using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

public class TcpPortForwarder
{
    private readonly IPAddress localIp = IPAddress.Any;
    private readonly int localPort = 3390; // Local port to listen on
    private readonly string remoteIp = "192.168.32.206"; // Remote IP to forward to
    private readonly int remotePort = 3389; // Remote port (e.g., RDP port)

    public async Task StartForwarding()
    {
        TcpListener listener = new TcpListener(localIp, localPort);
        listener.Start();
        Console.WriteLine($"Listening on {localIp}:{localPort}...");

        while (true)
        {
            var client = await listener.AcceptTcpClientAsync();
            _ = HandleClient(client);
        }
    }

    private async Task HandleClient(TcpClient client)
    {
        using (client)
        using (var remoteClient = new TcpClient())
        {
            await remoteClient.ConnectAsync(remoteIp, remotePort);
            var clientStream = client.GetStream();
            var remoteStream = remoteClient.GetStream();

            Task clientToRemote = Task.Run(() => TransferData(clientStream, remoteStream));
            Task remoteToClient = Task.Run(() => TransferData(remoteStream, clientStream));
            await Task.WhenAll(clientToRemote, remoteToClient);
        }
    }

    private async Task TransferData(NetworkStream input, NetworkStream output)
    {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            await output.WriteAsync(buffer, 0, bytesRead);
        }
    }
}
